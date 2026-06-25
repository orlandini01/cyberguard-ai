"""
test_threat_detector.py — Testes do motor de detecção de ameaças.
"""
import pytest
import pandas as pd
from datetime import datetime, timedelta
from src.threat_detector import (
    detect_all_threats, detect_brute_force, detect_success_after_failure,
    detect_off_hours_access, detect_suspicious_ip,
    detect_user_enumeration, detect_privileged_access,
    ThreatEvent,
)


# ─── Helpers ─────────────────────────────────────────────────
def make_df(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

def make_event(ts, ip, user, action="LOGIN", status="failure", details=""):
    return {"timestamp": ts, "source_ip": ip, "username": user,
            "action": action, "status": status, "details": details}

NOW = datetime(2024, 6, 17, 14, 0, 0)   # segunda-feira, 14h (horário comercial)
NIGHT = datetime(2024, 6, 17, 2, 0, 0)  # segunda-feira, 2h (off-hours)
SAT = datetime(2024, 6, 15, 14, 0, 0)   # sábado, 14h (fim de semana)


# ─── RN-01: Brute Force ──────────────────────────────────────
class TestBruteForce:
    def test_detects_5_failures_in_window(self):
        rows = [make_event(NOW + timedelta(minutes=i), "1.2.3.4", "admin")
                for i in range(5)]
        df = make_df(rows)
        threats = detect_brute_force(df)
        assert len(threats) >= 1
        assert threats[0].incident_type == "BRUTE_FORCE"

    def test_detects_with_more_than_threshold(self):
        rows = [make_event(NOW + timedelta(minutes=i), "1.2.3.4", "root")
                for i in range(10)]
        df = make_df(rows)
        threats = detect_brute_force(df)
        assert len(threats) >= 1

    def test_no_detection_below_threshold(self):
        rows = [make_event(NOW + timedelta(minutes=i), "1.2.3.4", "admin")
                for i in range(4)]  # apenas 4 falhas
        df = make_df(rows)
        threats = detect_brute_force(df)
        assert len(threats) == 0

    def test_no_detection_outside_window(self):
        # 5 falhas mas espalhadas em 60 minutos (fora da janela de 10)
        rows = [make_event(NOW + timedelta(minutes=i * 15), "5.5.5.5", "user1")
                for i in range(5)]
        df = make_df(rows)
        threats = detect_brute_force(df)
        assert len(threats) == 0

    def test_base_score_is_70(self):
        rows = [make_event(NOW + timedelta(minutes=i), "1.2.3.4", "admin")
                for i in range(6)]
        df = make_df(rows)
        threats = detect_brute_force(df)
        assert threats[0].base_score == 70.0

    def test_no_detection_from_successes_only(self):
        rows = [make_event(NOW + timedelta(minutes=i), "1.2.3.4", "admin",
                           status="success") for i in range(6)]
        df = make_df(rows)
        threats = detect_brute_force(df)
        assert len(threats) == 0


# ─── RN-02: Success After Failure ────────────────────────────
class TestSuccessAfterFailure:
    def test_detects_success_after_3_failures(self):
        rows = [make_event(NOW + timedelta(minutes=i), "2.2.2.2", "joao")
                for i in range(3)]
        rows.append(make_event(NOW + timedelta(minutes=4), "2.2.2.2", "joao",
                               status="success"))
        df = make_df(rows)
        threats = detect_success_after_failure(df)
        assert len(threats) == 1
        assert threats[0].incident_type == "SUCCESS_AFTER_FAILURE"

    def test_base_score_is_85(self):
        rows = [make_event(NOW + timedelta(minutes=i), "2.2.2.2", "joao")
                for i in range(3)]
        rows.append(make_event(NOW + timedelta(minutes=5), "2.2.2.2", "joao",
                               status="success"))
        df = make_df(rows)
        threats = detect_success_after_failure(df)
        assert threats[0].base_score == 85.0

    def test_no_detection_without_prior_failures(self):
        rows = [make_event(NOW, "3.3.3.3", "maria", status="success")]
        df = make_df(rows)
        threats = detect_success_after_failure(df)
        assert len(threats) == 0

    def test_no_detection_below_failure_threshold(self):
        rows = [make_event(NOW + timedelta(minutes=i), "4.4.4.4", "pedro")
                for i in range(2)]  # apenas 2 falhas
        rows.append(make_event(NOW + timedelta(minutes=3), "4.4.4.4", "pedro",
                               status="success"))
        df = make_df(rows)
        threats = detect_success_after_failure(df)
        assert len(threats) == 0


# ─── RN-03: Off-Hours ────────────────────────────────────────
class TestOffHoursAccess:
    def test_detects_night_access(self):
        rows = [make_event(NIGHT + timedelta(minutes=i), "5.5.5.5", "ana",
                           status="success") for i in range(3)]
        df = make_df(rows)
        threats = detect_off_hours_access(df)
        assert len(threats) >= 1
        assert threats[0].incident_type == "OFF_HOURS_ACCESS"

    def test_detects_weekend_access(self):
        rows = [make_event(SAT + timedelta(hours=i), "6.6.6.6", "carlos",
                           status="success") for i in range(3)]
        df = make_df(rows)
        threats = detect_off_hours_access(df)
        assert len(threats) >= 1

    def test_no_detection_during_business_hours(self):
        rows = [make_event(NOW + timedelta(hours=i), "7.7.7.7", "luiza",
                           status="success") for i in range(3)]
        df = make_df(rows)
        threats = detect_off_hours_access(df)
        assert len(threats) == 0

    def test_base_score_is_40(self):
        rows = [make_event(NIGHT + timedelta(minutes=i), "8.8.8.8", "diego",
                           status="success") for i in range(3)]
        df = make_df(rows)
        threats = detect_off_hours_access(df)
        assert threats[0].base_score == 40.0


# ─── RN-04: Suspicious IP ────────────────────────────────────
class TestSuspiciousIp:
    def test_detects_ip_with_multiple_users(self):
        rows = [make_event(NOW + timedelta(minutes=i), "9.9.9.9", f"user{i:02d}")
                for i in range(5)]
        df = make_df(rows)
        threats = detect_suspicious_ip(df)
        assert len(threats) >= 1
        assert threats[0].incident_type == "SUSPICIOUS_IP"

    def test_no_detection_below_user_threshold(self):
        rows = [make_event(NOW, "10.10.10.10", "user01"),
                make_event(NOW + timedelta(minutes=1), "10.10.10.10", "user01"),
                make_event(NOW + timedelta(minutes=2), "10.10.10.10", "user02")]
        df = make_df(rows)
        threats = detect_suspicious_ip(df)
        assert len(threats) == 0

    def test_base_score_is_60(self):
        rows = [make_event(NOW + timedelta(minutes=i), "11.11.11.11", f"u{i}")
                for i in range(4)]
        df = make_df(rows)
        threats = detect_suspicious_ip(df)
        assert threats[0].base_score == 60.0


# ─── RN-05: User Enumeration ─────────────────────────────────
class TestUserEnumeration:
    def test_detects_10_distinct_users(self):
        rows = [make_event(NOW + timedelta(seconds=i * 30), "12.12.12.12",
                           f"testuser{i:03d}") for i in range(12)]
        df = make_df(rows)
        threats = detect_user_enumeration(df)
        assert len(threats) >= 1
        assert threats[0].incident_type == "USER_ENUMERATION"

    def test_no_detection_below_10(self):
        rows = [make_event(NOW + timedelta(minutes=i), "13.13.13.13", f"u{i}")
                for i in range(9)]
        df = make_df(rows)
        threats = detect_user_enumeration(df)
        assert len(threats) == 0

    def test_base_score_is_75(self):
        rows = [make_event(NOW + timedelta(seconds=i * 10), "14.14.14.14",
                           f"user{i:02d}") for i in range(11)]
        df = make_df(rows)
        threats = detect_user_enumeration(df)
        assert threats[0].base_score == 75.0


# ─── RN-06: Privileged Access ────────────────────────────────
class TestPrivilegedAccess:
    def test_detects_admin_failure(self):
        rows = [make_event(NOW + timedelta(minutes=i), "15.15.15.15", "admin")
                for i in range(3)]
        df = make_df(rows)
        threats = detect_privileged_access(df)
        assert len(threats) >= 1
        assert threats[0].incident_type == "PRIVILEGED_ACCESS"

    def test_detects_root_off_hours(self):
        rows = [make_event(NIGHT + timedelta(minutes=i), "16.16.16.16", "root",
                           status="success") for i in range(2)]
        df = make_df(rows)
        threats = detect_privileged_access(df)
        assert len(threats) >= 1

    def test_no_detection_normal_admin_business_hours(self):
        # admin com sucesso em horário comercial — não é ameaça
        rows = [make_event(NOW + timedelta(hours=i), "17.17.17.17", "admin",
                           status="success") for i in range(2)]
        df = make_df(rows)
        threats = detect_privileged_access(df)
        assert len(threats) == 0

    def test_base_score_is_50(self):
        rows = [make_event(NOW, "18.18.18.18", "administrator")]
        df = make_df(rows)
        threats = detect_privileged_access(df)
        assert threats[0].base_score == 50.0


# ─── detect_all_threats ───────────────────────────────────────
class TestDetectAllThreats:
    def test_returns_list(self, sample_df):
        result = detect_all_threats(sample_df)
        assert isinstance(result, list)

    def test_sorted_by_score_desc(self, sample_df):
        result = detect_all_threats(sample_df)
        if len(result) > 1:
            scores = [t.base_score for t in result]
            assert scores == sorted(scores, reverse=True)

    def test_empty_df_returns_empty(self):
        result = detect_all_threats(pd.DataFrame())
        assert result == []

    def test_clean_df_produces_no_high_score(self, clean_df):
        result = detect_all_threats(clean_df)
        # Logs limpos não devem ter incidentes de score alto
        high = [t for t in result if t.base_score >= 70]
        assert len(high) == 0