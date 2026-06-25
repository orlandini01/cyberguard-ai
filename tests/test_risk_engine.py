"""
test_risk_engine.py — Testes do motor de cálculo de risco.
"""
import pytest
from datetime import datetime
from src.threat_detector import ThreatEvent
from src.risk_engine import (
    calculate_risk, apply_frequency_factor,
    apply_off_hours_factor, apply_privilege_factor, score_all_threats,
)

NOW   = datetime(2024, 6, 17, 14, 0, 0)   # horário comercial
NIGHT = datetime(2024, 6, 17,  2, 0, 0)   # off-hours


def make_threat(incident_type="BRUTE_FORCE", base_score=70.0,
                user="joao", count=5, ts=NOW):
    return ThreatEvent(
        incident_type=incident_type, source_ip="1.2.3.4",
        target_user=user, first_seen=ts, last_seen=ts,
        event_count=count, base_score=base_score, description="test",
    )


class TestScoreNeverExceeds100:
    def test_capped_at_100(self):
        t = make_threat(base_score=100.0, count=100, user="admin", ts=NIGHT)
        score, _ = calculate_risk(t)
        assert score <= 100.0

    def test_brute_force_admin_night_is_critical(self):
        t = make_threat("BRUTE_FORCE", base_score=70.0,
                        user="admin", count=15, ts=NIGHT)
        score, severity = calculate_risk(t)
        assert severity == "critical"
        assert score >= 75.0

    def test_low_count_low_score(self):
        t = make_threat("OFF_HOURS_ACCESS", base_score=40.0,
                        user="joao", count=2, ts=NOW)
        score, _ = calculate_risk(t)
        assert score < 75.0


class TestFrequencyFactor:
    def test_at_threshold_gives_1x(self):
        result = apply_frequency_factor(70.0, count=5, threshold=5)
        assert result == pytest.approx(70.0)

    def test_double_threshold_gives_2x(self):
        result = apply_frequency_factor(70.0, count=10, threshold=5)
        assert result == pytest.approx(140.0)

    def test_capped_at_3x(self):
        result = apply_frequency_factor(70.0, count=100, threshold=5)
        assert result == pytest.approx(210.0)

    def test_zero_threshold_safe(self):
        result = apply_frequency_factor(50.0, count=10, threshold=0)
        assert result == 50.0


class TestOffHoursFactor:
    def test_off_hours_increases_30_percent(self):
        result = apply_off_hours_factor(100.0, True)
        assert result == pytest.approx(130.0)

    def test_business_hours_no_change(self):
        result = apply_off_hours_factor(100.0, False)
        assert result == pytest.approx(100.0)


class TestPrivilegeFactor:
    def test_admin_increases_50_percent(self):
        result = apply_privilege_factor(100.0, "admin")
        assert result == pytest.approx(150.0)

    def test_root_increases_50_percent(self):
        result = apply_privilege_factor(80.0, "root")
        assert result == pytest.approx(120.0)

    def test_normal_user_no_change(self):
        result = apply_privilege_factor(100.0, "joao.silva")
        assert result == pytest.approx(100.0)

    def test_administrator_prefix_detected(self):
        result = apply_privilege_factor(60.0, "administrator")
        assert result == pytest.approx(90.0)


class TestScoreAllThreats:
    def test_returns_list_of_dicts(self):
        threats = [make_threat()]
        result = score_all_threats(threats)
        assert isinstance(result, list)
        assert isinstance(result[0], dict)

    def test_result_has_required_keys(self):
        threats = [make_threat()]
        result = score_all_threats(threats)
        for key in ["risk_score", "severity", "incident_type", "source_ip"]:
            assert key in result[0]

    def test_sorted_by_risk_score_desc(self):
        threats = [
            make_threat("BRUTE_FORCE",   base_score=70.0, count=5),
            make_threat("OFF_HOURS_ACCESS", base_score=40.0, count=2),
            make_threat("USER_ENUMERATION", base_score=75.0, count=10),
        ]
        result = score_all_threats(threats)
        scores = [r["risk_score"] for r in result]
        assert scores == sorted(scores, reverse=True)

    def test_empty_list(self):
        assert score_all_threats([]) == []