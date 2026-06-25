"""02_analysis.py — Página de análise de ameaças."""
import sys, os, pickle
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
os.environ["PYTHONPATH"] = str(_ROOT)

import streamlit as st
import pandas as pd

from src.threat_detector import INCIDENT_LABELS
from src.utils import severity_label, severity_to_color

st.set_page_config(page_title="Análise | CyberGuard AI", page_icon="🔍", layout="wide")

st.markdown("""
<style>
.incident-card {
    background: #111827; border: 1px solid #1F2937;
    border-radius: 12px; padding: 1.25rem 1.5rem;
    margin-bottom: 0.75rem;
    border-left: 5px solid var(--c, #6B7280);
}
.inc-type { font-size:0.7rem; font-weight:600; text-transform:uppercase;
            letter-spacing:0.08em; color:#6B7280; margin-bottom:4px; }
.inc-desc { font-size:0.9rem; color:#D1D5DB; margin: 4px 0 8px 0; }
.inc-meta { font-size:0.75rem; color:#4B5563; }
.badge { display:inline-block; padding:3px 10px; border-radius:9999px;
         font-size:0.72rem; font-weight:700; letter-spacing:0.04em; }
</style>
""", unsafe_allow_html=True)

st.title("🔍 Análise de Ameaças")

# ─── Recupera dados: sessão → disco ──────────────────────────
STATE_FILE = _ROOT / "reports" / ".session_state.pkl"

scored = st.session_state.get("scored_threats")

if not scored and STATE_FILE.exists():
    try:
        with open(STATE_FILE, "rb") as f:
            disk = pickle.load(f)
        scored = disk["scored"]
        # Restaura sessão completa
        st.session_state["scored_threats"] = scored
        st.session_state["analysis_data"]  = scored
        st.session_state["raw_df"]         = disk["df"]
        st.session_state["filename"]       = disk["filename"]
        st.caption(f"♻️ Análise restaurada do disco: **{disk['filename']}**")
    except Exception:
        scored = None

if not scored:
    st.warning("⚠️ Nenhuma análise encontrada. Vá em **Importar Logs**, carregue um arquivo e clique em **Executar Análise**.")
    st.stop()

filename = st.session_state.get("filename", "arquivo")
st.caption(f"Arquivo: **{filename}** · {len(scored)} incidente(s) detectado(s)")

# ─── KPIs ────────────────────────────────────────────────────
st.markdown("---")
total     = len(scored)
critical  = sum(1 for s in scored if s["severity"] == "critical")
high      = sum(1 for s in scored if s["severity"] == "high")
medium    = sum(1 for s in scored if s["severity"] == "medium")
low       = sum(1 for s in scored if s["severity"] == "low")
avg_score = round(sum(s["risk_score"] for s in scored) / total, 1) if total else 0

c1,c2,c3,c4,c5,c6 = st.columns(6)
c1.metric("Total Incidentes", total)
c2.metric("🔴 Crítico", critical)
c3.metric("🟠 Alto",    high)
c4.metric("🟡 Médio",   medium)
c5.metric("🟢 Baixo",   low)
c6.metric("Score Médio", avg_score)

# ─── Filtros ─────────────────────────────────────────────────
st.markdown("---")
cf1, cf2 = st.columns(2)
with cf1:
    sev_filter = st.multiselect(
        "Severidade:", ["critical","high","medium","low"],
        default=["critical","high","medium","low"],
        format_func=lambda x: severity_label(x),
    )
with cf2:
    type_filter = st.multiselect(
        "Tipo de incidente:", list(INCIDENT_LABELS.keys()),
        default=list(INCIDENT_LABELS.keys()),
        format_func=lambda x: INCIDENT_LABELS.get(x, x),
    )

filtered = [s for s in scored
            if s["severity"] in sev_filter and s["incident_type"] in type_filter]

st.markdown(f"**{len(filtered)} incidente(s) exibido(s)**")

# ─── Cards ───────────────────────────────────────────────────
SEV_COLORS = {"critical":"#EF4444","high":"#F97316","medium":"#EAB308","low":"#22C55E"}
SEV_EMOJI  = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢"}

for inc in filtered:
    color = SEV_COLORS.get(inc["severity"], "#6B7280")
    emoji = SEV_EMOJI.get(inc["severity"], "⚪")
    label = INCIDENT_LABELS.get(inc["incident_type"], inc["incident_type"])
    ts    = inc["first_seen"].strftime("%d/%m/%Y %H:%M")

    st.markdown(f"""
    <div class="incident-card" style="--c:{color}">
        <div class="inc-type">{inc['incident_type']}</div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
            <span style="font-size:1rem;font-weight:700;color:#F9FAFB;">{label}</span>
            <span class="badge" style="background:{color}22;color:{color};border:1px solid {color}55;">
                {emoji} {inc['severity'].upper()} · {inc['risk_score']}
            </span>
        </div>
        <div class="inc-desc">{inc['description']}</div>
        <div class="inc-meta">
            🌐 IP: <b>{inc['source_ip']}</b> &nbsp;|&nbsp;
            👤 Alvo: <b>{inc['target_user']}</b> &nbsp;|&nbsp;
            📅 {ts} &nbsp;|&nbsp; 📋 {inc['event_count']} eventos
        </div>
    </div>
    """, unsafe_allow_html=True)

# ─── Tabela resumo ───────────────────────────────────────────
st.markdown("---")
with st.expander("📋 Tabela resumo"):
    rows = [{
        "Tipo":      INCIDENT_LABELS.get(s["incident_type"], s["incident_type"]),
        "IP":        s["source_ip"],
        "Usuário":   s["target_user"],
        "Score":     s["risk_score"],
        "Severidade":severity_label(s["severity"]),
        "Eventos":   s["event_count"],
        "Primeiro":  s["first_seen"].strftime("%d/%m/%Y %H:%M"),
    } for s in filtered]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)