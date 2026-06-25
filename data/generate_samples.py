"""
generate_samples.py — Gerador de logs fictícios realistas para o CyberGuard AI.
Execute: python data/generate_samples.py
"""

import csv
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)

# ─── Configurações ────────────────────────────────────────────
OUTPUT_DIR = Path(__file__).parent
START_DATE = datetime.now() - timedelta(days=30)

# ─── Dados fictícios ──────────────────────────────────────────
INTERNAL_IPS = [f"10.0.{random.randint(0,5)}.{random.randint(1,254)}" for _ in range(30)]
LEGIT_IPS    = [f"189.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(20)]

ATTACKER_IPS = [
    "185.220.101.47",  # Tor exit node (fictício)
    "45.142.212.100",
    "194.165.16.72",
    "91.108.4.201",
    "203.0.113.42",    # TEST-NET (RFC 5737, seguro para docs)
    "198.51.100.77",   # TEST-NET
    "192.0.2.33",      # TEST-NET
]

NORMAL_USERS = [
    "ana.lima", "carlos.mendes", "fernanda.costa", "joao.silva",
    "lucia.santos", "marcos.oliveira", "patricia.rocha", "roberto.alves",
    "sandra.ferreira", "thiago.pereira", "vanessa.souza", "william.nunes",
    "beatriz.campos", "diego.martins", "elena.barbosa", "fabio.carvalho",
]

PRIVILEGED_USERS = ["admin", "root", "administrator", "sa", "sysadmin", "dbadmin"]

ACTIONS = {
    "login":      ["LOGIN", "SSH_LOGIN", "RDP_LOGIN", "VPN_LOGIN", "FTP_LOGIN"],
    "access":     ["FILE_ACCESS", "DB_QUERY", "API_CALL", "WEB_REQUEST"],
    "admin":      ["USER_CREATE", "PASSWD_CHANGE", "SUDO", "PRIVILEGE_ESCALATION"],
    "network":    ["PORT_SCAN", "FIREWALL_BLOCK", "CONNECTION_ATTEMPT"],
}

DETAILS_SUCCESS = [
    "Autenticação bem-sucedida", "Sessão iniciada", "Acesso autorizado",
    "Login via 2FA", "Credenciais válidas", "Token válido",
]
DETAILS_FAILURE = [
    "Credenciais inválidas", "Senha incorreta", "Usuário não encontrado",
    "Conta bloqueada", "Token expirado", "MFA falhou",
    "Tentativa de acesso não autorizado", "IP bloqueado por política",
]

def rand_time(base: datetime, offset_hours: float = 0, jitter_minutes: int = 30) -> datetime:
    return base + timedelta(hours=offset_hours, minutes=random.randint(0, jitter_minutes), seconds=random.randint(0, 59))

def business_hour_time(base_day: datetime) -> datetime:
    """Gera timestamp em horário comercial (8h-18h, seg-sex)."""
    day = base_day
    # Garante dia útil
    while day.weekday() >= 5:
        day += timedelta(days=1)
    return day.replace(hour=random.randint(8, 17), minute=random.randint(0, 59), second=random.randint(0, 59))

def off_hour_time(base_day: datetime) -> datetime:
    """Gera timestamp fora do horário comercial."""
    hour = random.choice([0, 1, 2, 3, 4, 5, 22, 23])
    return base_day.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))

def weekend_time(base_day: datetime) -> datetime:
    """Gera timestamp no fim de semana."""
    days_ahead = (5 - base_day.weekday()) % 7
    if days_ahead == 0:
        days_ahead = 7
    saturday = base_day + timedelta(days=days_ahead)
    return saturday.replace(hour=random.randint(10, 22), minute=random.randint(0, 59))

# ─── Geradores de cenários ────────────────────────────────────

def gen_normal_logins(count=200) -> list[dict]:
    """Logins normais em horário comercial."""
    events = []
    for i in range(count):
        base = START_DATE + timedelta(days=random.randint(0, 29))
        ts   = business_hour_time(base)
        user = random.choice(NORMAL_USERS)
        ip   = random.choice(INTERNAL_IPS + LEGIT_IPS)
        action = random.choice(ACTIONS["login"])
        events.append({
            "timestamp": ts,
            "source_ip": ip,
            "username":  user,
            "action":    action,
            "status":    "success",
            "details":   random.choice(DETAILS_SUCCESS),
        })
    return events

def gen_brute_force(count=4) -> list[dict]:
    """
    RN-01: 5+ falhas do mesmo IP em 10 minutos.
    Gera 4 atacantes distintos.
    """
    events = []
    for _ in range(count):
        attacker_ip = random.choice(ATTACKER_IPS)
        target_user = random.choice(NORMAL_USERS + PRIVILEGED_USERS)
        base = START_DATE + timedelta(days=random.randint(0, 28))
        base = base.replace(hour=random.randint(1, 5))  # madrugada
        fail_count = random.randint(8, 20)
        for i in range(fail_count):
            ts = base + timedelta(minutes=i * random.uniform(0.3, 1.2))
            events.append({
                "timestamp": ts,
                "source_ip": attacker_ip,
                "username":  target_user,
                "action":    random.choice(["SSH_LOGIN", "LOGIN", "RDP_LOGIN"]),
                "status":    "failure",
                "details":   random.choice(DETAILS_FAILURE),
            })
    return events

def gen_success_after_failure(count=3) -> list[dict]:
    """
    RN-02: Múltiplas falhas seguidas de sucesso (comprometimento potencial).
    """
    events = []
    for _ in range(count):
        attacker_ip = random.choice(ATTACKER_IPS)
        target_user = random.choice(NORMAL_USERS)
        base = START_DATE + timedelta(days=random.randint(5, 25))
        base = base.replace(hour=random.randint(0, 4))
        fail_count = random.randint(3, 7)
        for i in range(fail_count):
            ts = base + timedelta(minutes=i * random.uniform(1, 3))
            events.append({
                "timestamp": ts,
                "source_ip": attacker_ip,
                "username":  target_user,
                "action":    "LOGIN",
                "status":    "failure",
                "details":   "Senha incorreta",
            })
        # Sucesso final — comprometimento
        ts_success = base + timedelta(minutes=fail_count * 2 + random.randint(1, 5))
        events.append({
            "timestamp": ts_success,
            "source_ip": attacker_ip,
            "username":  target_user,
            "action":    "LOGIN",
            "status":    "success",
            "details":   "Autenticação bem-sucedida",
        })
    return events

def gen_off_hours_access(count=30) -> list[dict]:
    """RN-03: Acessos legítimos e suspeitos em horários incomuns."""
    events = []
    for _ in range(count):
        base = START_DATE + timedelta(days=random.randint(0, 29))
        is_weekend = random.random() < 0.4
        ts = weekend_time(base) if is_weekend else off_hour_time(base)
        user = random.choice(NORMAL_USERS)
        ip   = random.choice(INTERNAL_IPS + ATTACKER_IPS[:2])
        events.append({
            "timestamp": ts,
            "source_ip": ip,
            "username":  user,
            "action":    random.choice(ACTIONS["login"] + ACTIONS["access"]),
            "status":    random.choice(["success", "success", "failure"]),
            "details":   "Acesso fora do horário padrão",
        })
    return events

def gen_suspicious_ip(count=3) -> list[dict]:
    """RN-04: Um IP tentando múltiplos usuários diferentes."""
    events = []
    for _ in range(count):
        attacker_ip = random.choice(ATTACKER_IPS)
        # Mesmo IP → muitos usuários distintos
        targets = random.sample(NORMAL_USERS, k=random.randint(5, 10))
        base = START_DATE + timedelta(days=random.randint(0, 20))
        base = base.replace(hour=random.randint(2, 6))
        for i, user in enumerate(targets):
            ts = base + timedelta(minutes=i * random.uniform(0.5, 2))
            events.append({
                "timestamp": ts,
                "source_ip": attacker_ip,
                "username":  user,
                "action":    "LOGIN",
                "status":    "failure",
                "details":   "Usuário não encontrado",
            })
    return events

def gen_user_enumeration(count=2) -> list[dict]:
    """RN-05: IP tentando 10+ usernames diferentes (enumeração)."""
    events = []
    for _ in range(count):
        attacker_ip = random.choice(ATTACKER_IPS)
        # Mistura de usuários reais e fictícios (enumeração)
        fake_users = [f"user{i:03d}" for i in range(1, 20)] + NORMAL_USERS[:5]
        targets = random.sample(fake_users, k=random.randint(12, 18))
        base = START_DATE + timedelta(days=random.randint(0, 15))
        base = base.replace(hour=random.randint(1, 4))
        for i, user in enumerate(targets):
            ts = base + timedelta(seconds=i * random.randint(10, 45))
            events.append({
                "timestamp": ts,
                "source_ip": attacker_ip,
                "username":  user,
                "action":    "LOGIN",
                "status":    "failure",
                "details":   "Usuário não encontrado",
            })
    return events

def gen_privileged_access(count=20) -> list[dict]:
    """RN-06: Acessos a contas privilegiadas — alguns suspeitos."""
    events = []
    for i in range(count):
        is_suspicious = i < 8  # primeiros 8 são suspeitos (fora do horário)
        base = START_DATE + timedelta(days=random.randint(0, 29))
        ts = off_hour_time(base) if is_suspicious else business_hour_time(base)
        priv_user = random.choice(PRIVILEGED_USERS)
        ip = random.choice(ATTACKER_IPS if is_suspicious else INTERNAL_IPS)
        status = "failure" if is_suspicious and random.random() < 0.7 else "success"
        events.append({
            "timestamp": ts,
            "source_ip": ip,
            "username":  priv_user,
            "action":    random.choice(ACTIONS["admin"] + ACTIONS["login"]),
            "status":    status,
            "details":   "Acesso à conta privilegiada" + (" - horário incomum" if is_suspicious else ""),
        })
    return events

def gen_normal_activity(count=150) -> list[dict]:
    """Atividade normal de rede — acesso a arquivos, APIs, etc."""
    events = []
    for _ in range(count):
        base = START_DATE + timedelta(days=random.randint(0, 29))
        ts   = business_hour_time(base)
        user = random.choice(NORMAL_USERS)
        ip   = random.choice(INTERNAL_IPS)
        action = random.choice(ACTIONS["access"])
        events.append({
            "timestamp": ts,
            "source_ip": ip,
            "username":  user,
            "action":    action,
            "status":    "success",
            "details":   f"Acesso normal ao sistema",
        })
    return events

# ─── Compilar e embaralhar ────────────────────────────────────

def build_dataset() -> list[dict]:
    all_events = (
        gen_normal_logins(200)        # baseline normal
        + gen_brute_force(4)          # RN-01
        + gen_success_after_failure(3) # RN-02
        + gen_off_hours_access(30)    # RN-03
        + gen_suspicious_ip(3)        # RN-04
        + gen_user_enumeration(2)     # RN-05
        + gen_privileged_access(20)   # RN-06
        + gen_normal_activity(150)    # ruído realista
    )
    # Ordena por timestamp
    all_events.sort(key=lambda x: x["timestamp"])

    # Adiciona ID sequencial
    for i, ev in enumerate(all_events, 1):
        ev["event_id"] = i

    return all_events

# ─── Exportar CSV ─────────────────────────────────────────────

def export_csv(events: list[dict], path: Path) -> None:
    fieldnames = ["event_id", "timestamp", "source_ip", "username", "action", "status", "details"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for ev in events:
            row = {**ev, "timestamp": ev["timestamp"].strftime("%Y-%m-%d %H:%M:%S")}
            writer.writerow(row)
    print(f"  ✅ CSV  → {path}  ({len(events)} eventos)")

# ─── Exportar JSON ────────────────────────────────────────────

def export_json(events: list[dict], path: Path) -> None:
    json_events = []
    for ev in events:
        json_events.append({**ev, "timestamp": ev["timestamp"].strftime("%Y-%m-%dT%H:%M:%S")})
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"source": "CyberGuard AI Sample Data", "version": "1.0",
                   "generated_at": datetime.now().isoformat(),
                   "total_events": len(json_events),
                   "events": json_events}, f, indent=2, ensure_ascii=False)
    print(f"  ✅ JSON → {path}  ({len(events)} eventos)")

# ─── Exportar TXT (formato syslog) ────────────────────────────

def export_txt(events: list[dict], path: Path) -> None:
    # Formato: <timestamp> <hostname> <action>[<pid>]: <status> user=<user> src=<ip> msg=<details>
    lines = []
    for ev in events:
        ts  = ev["timestamp"].strftime("%b %d %H:%M:%S")
        pid = random.randint(1000, 9999)
        line = (
            f"{ts} cyberguard-srv {ev['action']}[{pid}]: "
            f"{ev['status'].upper()} "
            f"user={ev['username']} "
            f"src={ev['source_ip']} "
            f"msg=\"{ev['details']}\""
        )
        lines.append(line)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"  ✅ TXT  → {path}  ({len(events)} linhas)")

# ─── Main ─────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n🔧 Gerando dados simulados do CyberGuard AI...\n")
    events = build_dataset()

    print(f"  📊 Total de eventos gerados: {len(events)}")
    print(f"  📅 Período: {events[0]['timestamp'].strftime('%d/%m/%Y')} → {events[-1]['timestamp'].strftime('%d/%m/%Y')}\n")

    export_csv( events, OUTPUT_DIR / "sample_logs.csv")
    export_json(events, OUTPUT_DIR / "sample_logs.json")
    export_txt( events, OUTPUT_DIR / "sample_logs.txt")

    # ─── Resumo dos cenários gerados ─────────────────────────
    print("\n  📋 Cenários incluídos:")
    print("     🔴 Brute Force (RN-01):                  ~60 eventos (4 atacantes)")
    print("     🔴 Login Após Falhas (RN-02):            ~30 eventos (3 casos)")
    print("     🟠 Acesso Off-Hours (RN-03):             ~30 eventos")
    print("     🟠 IP Suspeito multi-user (RN-04):       ~40 eventos (3 IPs)")
    print("     🟡 Enumeração de Usuários (RN-05):       ~30 eventos (2 casos)")
    print("     🟡 Acesso Privilegiado (RN-06):          ~20 eventos")
    print("     🟢 Atividade Normal:                     ~350 eventos (baseline)")
    print("\n  ✅ Dados prontos em data/\n")
