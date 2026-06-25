"""05_history.py — Histórico de análises."""
import sys, os
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
os.environ["PYTHONPATH"] = str(_ROOT)

import streamlit as st
import pandas as pd

from src.database import init_db, get_analysis_history, get_analysis_incidents, get_stats_summary
from src.utils import severity_label

st.set_page_config(page_title="Histórico | CyberGuard AI", page_icon="📋", layout="wide")

# Garante que o banco existe
init_db()

st.title("📋 Histórico de Análises")

# ─── Estatísticas globais ─────────────────────────────────────
stats = get_stats_summary()
c1, c2, c3 = st.columns(3)
c1.metric("Total de Análises",   stats["total_analyses"])
c2.metric("Total de Incidentes", stats["total_incidents"])
c3.metric("🔴 Incidentes Críticos", stats["total_critical"])

st.markdown("---")

# ─── Lista de análises ────────────────────────────────────────
history = get_analysis_history(limit=20)

if not history:
    st.info("📭 Nenhuma análise salva ainda.\n\n"
            "Vá em **Importar Logs**, carregue um arquivo e execute a análise.")
    st.stop()

st.markdown(f"**{len(history)} análise(s) encontrada(s)**")

SEV_COLORS = {"critical":"#EF4444","high":"#F97316","medium":"#EAB308","low":"#22C55E"}

for row in history:
    with st.expander(
        f"📄 #{row['id']} · {row['filename']} · "
        f"{row['analyzed_at'].strftime('%d/%m/%Y %H:%M')} · "
        f"{row['total_incidents']} incidentes",
        expanded=(row == history[0])  # expande o mais recente
    ):
        c1, c2, c3, c4, c5, c6 = st.columns(6)
        c1.metric("Eventos",    row["total_events"])
        c2.metric("Incidentes", row["total_incidents"])
        c3.metric("🔴 Críticos", row["critical_count"])
        c4.metric("🟠 Altos",    row["high_count"])
        c5.metric("🟡 Médios",   row["medium_count"])
        c6.metric("Score Médio", row["avg_risk_score"])

        st.markdown("<br>", unsafe_allow_html=True)

        # Incidentes desta análise
        incidents = get_analysis_incidents(row["id"])
        if incidents:
            st.markdown("**Top incidentes:**")
            table = [{
                "Tipo":      inc["incident_type"],
                "IP":        inc["source_ip"],
                "Usuário":   inc["target_user"],
                "Score":     inc["risk_score"],
                "Severidade":severity_label(inc["severity"]),
                "Eventos":   inc["event_count"],
            } for inc in incidents[:10]]
            st.dataframe(pd.DataFrame(table), use_container_width=True, hide_index=True)

        # Botão para recarregar esta análise na sessão
        if st.button(f"🔄 Recarregar análise #{row['id']} na sessão",
                     key=f"reload_{row['id']}"):
            scored_reload = [{
                "incident_type": inc["incident_type"],
                "severity":      inc["severity"],
                "risk_score":    inc["risk_score"],
                "source_ip":     inc["source_ip"],
                "target_user":   inc["target_user"],
                "first_seen":    inc["first_seen"],
                "last_seen":     inc["last_seen"],
                "event_count":   inc["event_count"],
                "description":   inc["description"],
                "raw_events":    [],
            } for inc in incidents]
            st.session_state["scored_threats"] = scored_reload
            st.session_state["analysis_data"]  = scored_reload
            st.session_state["filename"]       = row["filename"]
            st.success(f"✅ Análise #{row['id']} recarregada! Acesse **Análise** na sidebar.")