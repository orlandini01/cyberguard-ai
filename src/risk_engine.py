"""
risk_engine.py — Cálculo de score de risco por incidente.

Fórmula (RN-07):
  score = base_score × fator_frequência × fator_horário × fator_privilégio
  score = min(score, 100.0)

Classificação (RN-08):
  0–24   → low
  25–49  → medium
  50–74  → high
  75–100 → critical
"""

from src.threat_detector import ThreatEvent
from src.utils import score_to_severity, is_off_hours, is_weekend

PRIVILEGED_PREFIXES = {"admin", "root", "sa", "administrator", "sysadmin", "dbadmin"}


def calculate_risk(event: ThreatEvent) -> tuple[float, str]:
    """
    Calcula score final de risco e severidade para um ThreatEvent.

    Returns:
        (score: float 0–100, severity: str)
    """
    score = event.base_score

    score = apply_frequency_factor(score, event.event_count, _get_threshold(event.incident_type))
    score = apply_off_hours_factor(score, _event_is_off_hours(event))
    score = apply_privilege_factor(score, event.target_user)

    score = round(min(score, 100.0), 2)
    severity = score_to_severity(score)
    return score, severity


def apply_frequency_factor(base_score: float, count: int, threshold: int) -> float:
    """
    Multiplica o score pela frequência relativa ao threshold.
    Máximo de 3× para evitar inflação excessiva.

    fator = min(count / threshold, 3.0)
    """
    if threshold <= 0:
        return base_score
    factor = min(count / threshold, 3.0)
    return base_score * factor


def apply_off_hours_factor(score: float, off_hours: bool) -> float:
    """Aumenta 30% se o evento ocorreu fora do horário comercial."""
    return score * 1.3 if off_hours else score


def apply_privilege_factor(score: float, username: str) -> float:
    """Aumenta 50% se a conta alvo é privilegiada."""
    u = str(username).lower()
    is_priv = any(u == p or u.startswith(p) for p in PRIVILEGED_PREFIXES)
    return score * 1.5 if is_priv else score


def _get_threshold(incident_type: str) -> int:
    """Retorna o threshold de referência por tipo de incidente."""
    thresholds = {
        "BRUTE_FORCE":           5,
        "SUCCESS_AFTER_FAILURE": 3,
        "OFF_HOURS_ACCESS":      2,
        "SUSPICIOUS_IP":         3,
        "USER_ENUMERATION":      10,
        "PRIVILEGED_ACCESS":     1,
    }
    return thresholds.get(incident_type, 1)


def _event_is_off_hours(event: ThreatEvent) -> bool:
    """Verifica se o incidente ocorreu majoritariamente fora do horário."""
    return is_off_hours(event.first_seen.hour) or is_weekend(event.first_seen)


def score_all_threats(threats: list) -> list[dict]:
    """
    Aplica calculate_risk em todos os threats e retorna lista
    de dicts enriquecidos com score e severity para uso no dashboard.
    """
    results = []
    for t in threats:
        score, severity = calculate_risk(t)
        results.append({
            "incident_type": t.incident_type,
            "source_ip":     t.source_ip,
            "target_user":   t.target_user,
            "first_seen":    t.first_seen,
            "last_seen":     t.last_seen,
            "event_count":   t.event_count,
            "description":   t.description,
            "base_score":    t.base_score,
            "risk_score":    score,
            "severity":      severity,
            "raw_events":    t.raw_events,
        })
    # Reordena pelo score final (pode diferir da ordem base)
    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return results