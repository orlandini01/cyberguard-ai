"""
test_utils.py — Testes para funções utilitárias.
Estes testes já funcionam na Fase 2 (sem dependências de fases futuras).
"""

import pytest
from src.utils import (
    score_to_severity,
    is_off_hours,
    is_weekend,
    severity_to_color,
    severity_label,
)
from datetime import datetime


class TestScoreToSeverity:
    def test_critical_at_75(self):
        assert score_to_severity(75.0) == "critical"

    def test_critical_at_100(self):
        assert score_to_severity(100.0) == "critical"

    def test_high_at_50(self):
        assert score_to_severity(50.0) == "high"

    def test_high_at_74(self):
        assert score_to_severity(74.9) == "high"

    def test_medium_at_25(self):
        assert score_to_severity(25.0) == "medium"

    def test_medium_at_49(self):
        assert score_to_severity(49.9) == "medium"

    def test_low_at_0(self):
        assert score_to_severity(0.0) == "low"

    def test_low_at_24(self):
        assert score_to_severity(24.9) == "low"


class TestOffHours:
    def test_midnight_is_off_hours(self):
        assert is_off_hours(0) is True

    def test_3am_is_off_hours(self):
        assert is_off_hours(3) is True

    def test_6am_is_off_hours(self):
        assert is_off_hours(6) is True

    def test_7am_is_business_hours(self):
        assert is_off_hours(7) is False

    def test_noon_is_business_hours(self):
        assert is_off_hours(12) is False

    def test_21h_is_business_hours(self):
        assert is_off_hours(21) is False

    def test_22h_is_off_hours(self):
        assert is_off_hours(22) is True

    def test_23h_is_off_hours(self):
        assert is_off_hours(23) is True


class TestIsWeekend:
    def test_monday_is_not_weekend(self):
        monday = datetime(2024, 6, 17)  # segunda-feira
        assert is_weekend(monday) is False

    def test_saturday_is_weekend(self):
        saturday = datetime(2024, 6, 15)  # sábado
        assert is_weekend(saturday) is True

    def test_sunday_is_weekend(self):
        sunday = datetime(2024, 6, 16)  # domingo
        assert is_weekend(sunday) is True


class TestSeverityHelpers:
    def test_color_critical(self):
        assert severity_to_color("critical") == "#EF4444"

    def test_color_low(self):
        assert severity_to_color("low") == "#22C55E"

    def test_label_critical(self):
        assert "Crítico" in severity_label("critical")

    def test_label_unknown_returns_input(self):
        result = severity_label("unknown")
        assert result == "unknown"
