"""
test_ai_assistant.py — Testes do módulo de IA explicativa.
"""
import pytest
from datetime import datetime
from src.ai_assistant import explain_incident, get_recommendations, _explain_offline

NOW   = datetime(2024, 6, 17, 14, 0, 0)
NIGHT = datetime(2024, 6, 17,  2, 0, 0)

def make_incident(incident_type="BRUTE_FORCE", severity="critical",
                  score=100.0, user="admin", count=10, ts=NOW):
    return {
        "incident_type": incident_type,
        "severity":      severity,
        "risk_score":    score,
        "source_ip":     "203.0.113.42",
        "target_user":   user,
        "event_count":   count,
        "description":   "Descrição de teste.",
        "first_seen":    ts,
        "last_seen":     ts,
        "raw_events":    [],
    }


class TestExplainOffline:
    """Testa o modo offline para todos os 6 tipos de incidente."""

    def test_brute_force_explanation_not_empty(self):
        inc = make_incident("BRUTE_FORCE")
        result = _explain_offline(inc)
        assert len(result) > 100

    def test_success_after_failure_explanation(self):
        inc = make_incident("SUCCESS_AFTER_FAILURE")
        result = _explain_offline(inc)
        assert len(result) > 100

    def test_off_hours_explanation(self):
        inc = make_incident("OFF_HOURS_ACCESS", ts=NIGHT)
        result = _explain_offline(inc)
        assert len(result) > 100

    def test_suspicious_ip_explanation(self):
        inc = make_incident("SUSPICIOUS_IP")
        result = _explain_offline(inc)
        assert len(result) > 100

    def test_user_enumeration_explanation(self):
        inc = make_incident("USER_ENUMERATION")
        result = _explain_offline(inc)
        assert len(result) > 100

    def test_privileged_access_explanation(self):
        inc = make_incident("PRIVILEGED_ACCESS", user="root")
        result = _explain_offline(inc)
        assert len(result) > 100

    def test_unknown_type_returns_generic(self):
        inc = make_incident("UNKNOWN_TYPE")
        result = _explain_offline(inc)
        assert len(result) > 50

    def test_explanation_contains_ip(self):
        inc = make_incident("BRUTE_FORCE")
        result = _explain_offline(inc)
        assert "203.0.113.42" in result

    def test_explanation_contains_username(self):
        inc = make_incident("BRUTE_FORCE", user="administrator")
        result = _explain_offline(inc)
        assert "administrator" in result

    def test_explanation_contains_event_count(self):
        inc = make_incident("BRUTE_FORCE", count=14)
        result = _explain_offline(inc)
        assert "14" in result

    def test_critical_severity_context(self):
        inc = make_incident("BRUTE_FORCE", severity="critical")
        result = _explain_offline(inc)
        assert "imediata" in result.lower() or "grave" in result.lower()

    def test_three_sections_present(self):
        inc = make_incident("BRUTE_FORCE")
        result = _explain_offline(inc)
        assert "O QUE ACONTECEU" in result
        assert "POR QUE É PERIGOSO" in result
        assert "O QUE FAZER AGORA" in result


class TestExplainIncident:
    """Testa o ponto de entrada principal (sempre usa modo offline em testes)."""

    def test_returns_string(self):
        inc = make_incident()
        result = explain_incident(inc)
        assert isinstance(result, str)

    def test_all_types_return_nonempty(self):
        types = [
            "BRUTE_FORCE", "SUCCESS_AFTER_FAILURE", "OFF_HOURS_ACCESS",
            "SUSPICIOUS_IP", "USER_ENUMERATION", "PRIVILEGED_ACCESS",
        ]
        for t in types:
            result = explain_incident(make_incident(t))
            assert len(result) > 50, f"Explicação vazia para {t}"

    def test_offline_mode_no_api_needed(self):
        """Garante que funciona 100% sem API key."""
        import os
        key_backup = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            result = explain_incident(make_incident())
            assert len(result) > 50
        finally:
            if key_backup:
                os.environ["ANTHROPIC_API_KEY"] = key_backup


class TestGetRecommendations:
    """Testa as recomendações por tipo de incidente."""

    def test_brute_force_has_recs(self):
        recs = get_recommendations("BRUTE_FORCE")
        assert len(recs) >= 3

    def test_all_types_have_recs(self):
        types = [
            "BRUTE_FORCE", "SUCCESS_AFTER_FAILURE", "OFF_HOURS_ACCESS",
            "SUSPICIOUS_IP", "USER_ENUMERATION", "PRIVILEGED_ACCESS",
        ]
        for t in types:
            recs = get_recommendations(t)
            assert len(recs) >= 2, f"Poucas recomendações para {t}"

    def test_unknown_type_returns_default(self):
        recs = get_recommendations("UNKNOWN_TYPE")
        assert len(recs) >= 1

    def test_rec_has_required_keys(self):
        recs = get_recommendations("BRUTE_FORCE")
        for rec in recs:
            assert "priority" in rec
            assert "title"    in rec
            assert "description" in rec

    def test_priorities_are_valid(self):
        valid = {"immediate", "short_term", "long_term"}
        recs = get_recommendations("BRUTE_FORCE")
        for rec in recs:
            assert rec["priority"] in valid

    def test_immediate_priority_exists(self):
        """Todo incidente grave deve ter pelo menos uma ação imediata."""
        for t in ["BRUTE_FORCE", "SUCCESS_AFTER_FAILURE", "USER_ENUMERATION"]:
            recs = get_recommendations(t)
            has_immediate = any(r["priority"] == "immediate" for r in recs)
            assert has_immediate, f"Sem ação imediata para {t}"