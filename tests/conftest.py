"""
conftest.py — Fixtures compartilhadas para os testes do CyberGuard AI.

Fixtures disponíveis:
- sample_df: DataFrame básico de logs normalizados
- brute_force_df: DataFrame com padrão de brute force
- clean_df: DataFrame sem ameaças (para testar falsos positivos)
"""

import pytest
import pandas as pd
from datetime import datetime, timedelta


@pytest.fixture
def sample_df() -> pd.DataFrame:
    """DataFrame com mix de eventos normais e suspeitos."""
    now = datetime(2024, 6, 15, 14, 30, 0)
    rows = []

    # 10 eventos normais de login
    for i in range(10):
        rows.append({
            "timestamp":  now + timedelta(minutes=i * 5),
            "source_ip":  f"10.0.0.{i + 1}",
            "username":   f"user{i + 1:02d}",
            "action":     "LOGIN",
            "status":     "success",
            "details":    "Normal login",
        })

    # 6 falhas do mesmo IP (brute force)
    attacker_ip = "185.220.101.99"
    for i in range(6):
        rows.append({
            "timestamp":  now + timedelta(minutes=i),
            "source_ip":  attacker_ip,
            "username":   "admin",
            "action":     "LOGIN",
            "status":     "failure",
            "details":    "Invalid credentials",
        })

    return pd.DataFrame(rows)


@pytest.fixture
def brute_force_df() -> pd.DataFrame:
    """DataFrame com padrão claro de brute force (5+ falhas em 10 min)."""
    now = datetime(2024, 6, 15, 2, 0, 0)  # horário suspeito
    rows = [
        {
            "timestamp":  now + timedelta(minutes=i),
            "source_ip":  "203.0.113.42",
            "username":   "root",
            "action":     "SSH_LOGIN",
            "status":     "failure",
            "details":    "Authentication failed",
        }
        for i in range(8)
    ]
    return pd.DataFrame(rows)


@pytest.fixture
def clean_df() -> pd.DataFrame:
    """DataFrame sem nenhuma ameaça — para testar falsos positivos."""
    now = datetime(2024, 6, 15, 10, 0, 0)  # horário comercial
    rows = [
        {
            "timestamp":  now + timedelta(minutes=i * 15),
            "source_ip":  f"192.168.1.{i + 1}",
            "username":   f"employee{i + 1:02d}",
            "action":     "LOGIN",
            "status":     "success",
            "details":    "Regular access",
        }
        for i in range(20)
    ]
    return pd.DataFrame(rows)
