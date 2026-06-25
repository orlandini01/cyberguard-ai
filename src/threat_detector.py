"""
threat_detector.py — Motor de detecção de ameaças baseado em regras.

Detectores:
  RN-01  BRUTE_FORCE           — 5+ falhas do mesmo IP em 10 min
  RN-02  SUCCESS_AFTER_FAILURE — login bem-sucedido após 3+ falhas
  RN-03  OFF_HOURS_ACCESS      — acesso fora do horário comercial
  RN-04  SUSPICIOUS_IP         — IP com 3+ usuários distintos
  RN-05  USER_ENUMERATION      — IP com 10+ usernames distintos com falha
  RN-06  PRIVILEGED_ACCESS     — acesso a contas admin/root fora do horário
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict

import pandas as pd
from loguru import logger

from src.utils import get_env_int, is_off_hours, is_weekend


# ─── Thresholds (configuráveis via .env) ─────────────────────
BF_THRESHOLD    = get_env_int("BRUTE_FORCE_THRESHOLD", 5)
BF_WINDOW_MIN   = get_env_int("BRUTE_FORCE_WINDOW_MINUTES", 10)
SAF_THRESHOLD   = get_env_int("SUCCESS_AFTER_FAIL_THRESHOLD", 3)
SUSP_IP_USERS   = get_env_int("SUSPICIOUS_IP_USER_THRESHOLD", 3)
ENUM_THRESHOLD  = 10

PRIVILEGED_PREFIXES = {"admin", "root", "sa", "administrator", "sysadmin", "dbadmin"}


# ─── Modelo de dados ─────────────────────────────────────────
@dataclass
class ThreatEvent:
    incident_type: str
    source_ip:     str
    target_user:   str
    first_seen:    datetime
    last_seen:     datetime
    event_count:   int
    description:   str
    base_score:    float
    raw_events:    list = field(default_factory=list)

    @property
    def duration_minutes(self) -> float:
        delta = self.last_seen - self.first_seen
        return delta.total_seconds() / 60


INCIDENT_LABELS = {
    "BRUTE_FORCE":           "Ataque de Força Bruta",
    "SUCCESS_AFTER_FAILURE": "Login Bem-sucedido Após Múltiplas Falhas",
    "OFF_HOURS_ACCESS":      "Acesso em Horário Incomum",
    "SUSPICIOUS_IP":         "Comportamento Suspeito de IP",
    "USER_ENUMERATION":      "Enumeração de Usuários",
    "PRIVILEGED_ACCESS":     "Acesso Privilegiado Suspeito",
}


# ─── Ponto de entrada ────────────────────────────────────────
def detect_all_threats(df: pd.DataFrame) -> list[ThreatEvent]:
    """
    Executa todos os detectores sobre o DataFrame de logs.
    Retorna lista de ThreatEvent ordenada por base_score desc.
    """
    if df.empty:
        return []

    threats: list[ThreatEvent] = []

    detectors = [
        detect_brute_force,
        detect_success_after_failure,
        detect_off_hours_access,
        detect_suspicious_ip,
        detect_user_enumeration,
        detect_privileged_access,
    ]

    for detector in detectors:
        try:
            found = detector(df)
            threats.extend(found)
            logger.info(f"{detector.__name__}: {len(found)} incidentes")
        except Exception as e:
            logger.error(f"Erro em {detector.__name__}: {e}")

    threats.sort(key=lambda t: t.base_score, reverse=True)
    logger.info(f"Total de ameaças detectadas: {len(threats)}")
    return threats


# ─── RN-01: Brute Force ──────────────────────────────────────
def detect_brute_force(df: pd.DataFrame) -> list[ThreatEvent]:
    """
    5+ falhas de autenticação do mesmo IP em janela de 10 minutos.
    Agrupa por (source_ip, username) e verifica janelas deslizantes.
    """
    threats = []
    failures = df[df["status"] == "failure"].copy()
    if failures.empty:
        return []

    window = timedelta(minutes=BF_WINDOW_MIN)

    for (ip, user), group in failures.groupby(["source_ip", "username"]):
        times = sorted(group["timestamp"].tolist())
        if len(times) < BF_THRESHOLD:
            continue

        # Janela deslizante
        i = 0
        while i < len(times):
            window_events = [t for t in times if times[i] <= t <= times[i] + window]
            if len(window_events) >= BF_THRESHOLD:
                raw = group[
                    (group["timestamp"] >= times[i]) &
                    (group["timestamp"] <= times[i] + window)
                ].to_dict("records")

                threats.append(ThreatEvent(
                    incident_type = "BRUTE_FORCE",
                    source_ip     = str(ip),
                    target_user   = str(user),
                    first_seen    = window_events[0],
                    last_seen     = window_events[-1],
                    event_count   = len(window_events),
                    base_score    = 70.0,
                    description   = (
                        f"{len(window_events)} tentativas de login malsucedidas "
                        f"de {ip} para o usuário '{user}' "
                        f"em {BF_WINDOW_MIN} minutos."
                    ),
                    raw_events    = raw,
                ))
                # Pula para depois da janela para evitar duplicatas
                i += len(window_events)
            else:
                i += 1

    return threats


# ─── RN-02: Success After Failure ────────────────────────────
def detect_success_after_failure(df: pd.DataFrame) -> list[ThreatEvent]:
    """
    Login bem-sucedido após 3+ falhas consecutivas do mesmo IP/usuário
    em janela de 30 minutos. Possível comprometimento de conta.
    """
    threats = []
    window = timedelta(minutes=30)

    for (ip, user), group in df.groupby(["source_ip", "username"]):
        events = group.sort_values("timestamp")
        times    = events["timestamp"].tolist()
        statuses = events["status"].tolist()

        for i, (ts, status) in enumerate(zip(times, statuses)):
            if status != "success":
                continue

            # Conta falhas anteriores na janela de 30 min
            window_start = ts - window
            prior_failures = [
                j for j in range(i)
                if statuses[j] == "failure" and times[j] >= window_start
            ]

            if len(prior_failures) >= SAF_THRESHOLD:
                raw = events.iloc[prior_failures + [i]].to_dict("records")
                threats.append(ThreatEvent(
                    incident_type = "SUCCESS_AFTER_FAILURE",
                    source_ip     = str(ip),
                    target_user   = str(user),
                    first_seen    = times[prior_failures[0]],
                    last_seen     = ts,
                    event_count   = len(prior_failures) + 1,
                    base_score    = 85.0,
                    description   = (
                        f"Login bem-sucedido para '{user}' (IP: {ip}) "
                        f"após {len(prior_failures)} falhas em 30 minutos. "
                        f"Possível comprometimento de conta."
                    ),
                    raw_events    = raw,
                ))
                break  # Um incidente por par ip/user

    return threats


# ─── RN-03: Off-Hours Access ─────────────────────────────────
def detect_off_hours_access(df: pd.DataFrame) -> list[ThreatEvent]:
    """
    Acessos fora do horário comercial (antes das 7h ou após as 22h)
    ou em fins de semana. Agrupa por IP para reduzir ruído.
    """
    threats = []

    off = df[df["timestamp"].apply(
        lambda ts: is_off_hours(ts.hour) or is_weekend(ts)
    )].copy()

    if off.empty:
        return []

    # Agrupa por IP — só alerta se o mesmo IP tem múltiplos eventos off-hours
    for ip, group in off.groupby("source_ip"):
        if len(group) < 2:
            continue

        users   = group["username"].unique().tolist()
        actions = group["action"].unique().tolist()
        times   = sorted(group["timestamp"].tolist())

        threats.append(ThreatEvent(
            incident_type = "OFF_HOURS_ACCESS",
            source_ip     = str(ip),
            target_user   = users[0] if len(users) == 1 else f"{len(users)} usuários",
            first_seen    = times[0],
            last_seen     = times[-1],
            event_count   = len(group),
            base_score    = 40.0,
            description   = (
                f"IP {ip} realizou {len(group)} acessos fora do horário comercial "
                f"envolvendo {len(users)} usuário(s) e {len(actions)} tipo(s) de ação."
            ),
            raw_events    = group.to_dict("records"),
        ))

    return threats


# ─── RN-04: Suspicious IP ────────────────────────────────────
def detect_suspicious_ip(df: pd.DataFrame) -> list[ThreatEvent]:
    """
    IP que tenta acessar 3+ usuários distintos.
    Indica scanning horizontal ou credential stuffing.
    """
    threats = []

    for ip, group in df.groupby("source_ip"):
        users = group["username"].nunique()
        if users < SUSP_IP_USERS:
            continue

        failures = group[group["status"] == "failure"]
        times    = sorted(group["timestamp"].tolist())
        user_list = group["username"].unique().tolist()

        threats.append(ThreatEvent(
            incident_type = "SUSPICIOUS_IP",
            source_ip     = str(ip),
            target_user   = f"{users} usuários distintos",
            first_seen    = times[0],
            last_seen     = times[-1],
            event_count   = len(group),
            base_score    = 60.0,
            description   = (
                f"IP {ip} tentou acessar {users} usuários distintos "
                f"({len(failures)} falhas de {len(group)} tentativas). "
                f"Possível credential stuffing ou varredura de contas."
            ),
            raw_events    = group.head(20).to_dict("records"),
        ))

    return threats


# ─── RN-05: User Enumeration ─────────────────────────────────
def detect_user_enumeration(df: pd.DataFrame) -> list[ThreatEvent]:
    """
    IP com 10+ usernames distintos com falha.
    Indica tentativa de enumerar contas válidas no sistema.
    """
    threats = []
    failures = df[df["status"] == "failure"]

    for ip, group in failures.groupby("source_ip"):
        distinct_users = group["username"].nunique()
        if distinct_users < ENUM_THRESHOLD:
            continue

        times = sorted(group["timestamp"].tolist())
        threats.append(ThreatEvent(
            incident_type = "USER_ENUMERATION",
            source_ip     = str(ip),
            target_user   = f"{distinct_users} usernames testados",
            first_seen    = times[0],
            last_seen     = times[-1],
            event_count   = len(group),
            base_score    = 75.0,
            description   = (
                f"IP {ip} testou {distinct_users} nomes de usuário diferentes, "
                f"todos com falha. Indica enumeração sistemática de contas."
            ),
            raw_events    = group.head(20).to_dict("records"),
        ))

    return threats


# ─── RN-06: Privileged Access ────────────────────────────────
def detect_privileged_access(df: pd.DataFrame) -> list[ThreatEvent]:
    """
    Acesso (com falha ou fora do horário) a contas privilegiadas
    como admin, root, sa, administrator.
    """
    threats = []

    def is_privileged(username: str) -> bool:
        u = str(username).lower()
        return any(u == p or u.startswith(p) for p in PRIVILEGED_PREFIXES)

    priv_df = df[df["username"].apply(is_privileged)].copy()
    if priv_df.empty:
        return []

    # Só alerta se há falhas OU acesso fora do horário
    suspicious = priv_df[
        (priv_df["status"] == "failure") |
        priv_df["timestamp"].apply(lambda ts: is_off_hours(ts.hour) or is_weekend(ts))
    ]

    if suspicious.empty:
        return []

    for (ip, user), group in suspicious.groupby(["source_ip", "username"]):
        times    = sorted(group["timestamp"].tolist())
        failures = (group["status"] == "failure").sum()
        off      = group["timestamp"].apply(lambda ts: is_off_hours(ts.hour)).sum()

        context = []
        if failures > 0:
            context.append(f"{failures} falha(s)")
        if off > 0:
            context.append(f"{off} evento(s) fora do horário")

        threats.append(ThreatEvent(
            incident_type = "PRIVILEGED_ACCESS",
            source_ip     = str(ip),
            target_user   = str(user),
            first_seen    = times[0],
            last_seen     = times[-1],
            event_count   = len(group),
            base_score    = 50.0,
            description   = (
                f"Atividade suspeita na conta privilegiada '{user}' "
                f"a partir de {ip}: {', '.join(context)}."
            ),
            raw_events    = group.to_dict("records"),
        ))

    return threats


# ─── Utilitários ─────────────────────────────────────────────
def threats_to_dataframe(threats: list[ThreatEvent]) -> pd.DataFrame:
    """Converte lista de ThreatEvent para DataFrame para exibição."""
    if not threats:
        return pd.DataFrame()

    rows = []
    for t in threats:
        rows.append({
            "tipo":          INCIDENT_LABELS.get(t.incident_type, t.incident_type),
            "ip_origem":     t.source_ip,
            "usuario_alvo":  t.target_user,
            "primeiro_evento": t.first_seen,
            "ultimo_evento": t.last_seen,
            "total_eventos": t.event_count,
            "score_base":    t.base_score,
            "descricao":     t.description,
            "incident_type": t.incident_type,
        })
    return pd.DataFrame(rows)