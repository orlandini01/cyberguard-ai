"""03_incidents.py — Detalhamento de incidentes com explicação por IA."""
import sys, os, pickle
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
os.environ["PYTHONPATH"] = str(_ROOT)

import streamlit as st
import pandas as pd

from src.threat_detector import INCIDENT_LABELS
from src.utils import severity_label, has_api_key
from src.ai_assistant import explain_incident, get_recommendations

st.set_page_config(page_title="Incidentes | CyberGuard AI", page_icon="⚠️", layout="wide")

STATE_FILE = _ROOT / "reports" / ".session_state.pkl"

scored = st.session_state.get("scored_threats")
if not scored and STATE_FILE.exists():
    try:
        with open(STATE_FILE, "rb") as f:
            disk = pickle.load(f)
        scored = disk["scored"]
        st.session_state["scored_threats"] = scored
        st.session_state["raw_df"]         = disk["df"]
        st.session_state["filename"]       = disk["filename"]
    except Exception:
        pass

st.title("⚠️ Detalhamento de Incidentes")

if not scored:
    st.warning("⚠️ Nenhuma análise encontrada. Vá em **Importar Logs** e execute a análise.")
    st.stop()

# ─── Seletor ──────────────────────────────────────────────────
st.markdown(f"**{len(scored)} incidente(s) disponível(is)**")

options = {
    f"#{i+1} · {INCIDENT_LABELS.get(s['incident_type'], s['incident_type'])} "
    f"· {s['source_ip']} · Score {s['risk_score']} · {s['severity'].upper()}": i
    for i, s in enumerate(scored)
}
selected_label = st.selectbox("Selecione um incidente:", list(options.keys()))
idx = options[selected_label]
inc = scored[idx]

# ─── Header ───────────────────────────────────────────────────
SEV_COLORS = {"critical":"#EF4444","high":"#F97316","medium":"#EAB308","low":"#22C55E"}
color = SEV_COLORS.get(inc["severity"], "#6B7280")
label = INCIDENT_LABELS.get(inc["incident_type"], inc["incident_type"])

st.markdown(f"""
<div style="background:#111827;border:1px solid #1F2937;border-left:6px solid {color};
            border-radius:14px;padding:1.5rem 2rem;margin:1rem 0;">
    <div style="font-size:0.7rem;color:#6B7280;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:6px;">
        {inc['incident_type']}
    </div>
    <div style="font-size:1.4rem;font-weight:700;color:#F9FAFB;margin-bottom:8px;">
        {label}
        <span style="font-size:0.8rem;background:{color}22;color:{color};border:1px solid {color}55;
                     padding:3px 10px;border-radius:9999px;margin-left:10px;vertical-align:middle;">
            {inc['severity'].upper()} · {inc['risk_score']}
        </span>
    </div>
    <div style="color:#9CA3AF;font-size:0.9rem;line-height:1.6;">{inc['description']}</div>
</div>
""", unsafe_allow_html=True)

# ─── Métricas ─────────────────────────────────────────────────
c1,c2,c3,c4,c5 = st.columns(5)
c1.metric("Score de Risco",   inc["risk_score"])
c2.metric("Severidade",       severity_label(inc["severity"]))
c3.metric("IP de Origem",     inc["source_ip"])
c4.metric("Usuário Alvo",     str(inc["target_user"]))
c5.metric("Total de Eventos", inc["event_count"])

st.markdown("<br>", unsafe_allow_html=True)
cc1, cc2 = st.columns(2)
cc1.info(f"📅 **Primeiro evento:** {inc['first_seen'].strftime('%d/%m/%Y %H:%M:%S')}")
cc2.info(f"📅 **Último evento:**   {inc['last_seen'].strftime('%d/%m/%Y %H:%M:%S')}")

# ─── Explicação por IA ────────────────────────────────────────
st.markdown("---")
st.markdown("#### 🤖 Explicação em Linguagem Simples")

ai_key = f"ai_explanation_{idx}"
mode_label = "Claude API" if has_api_key() else "Modo Offline (Templates)"

col_btn, col_mode = st.columns([2, 5])
with col_btn:
    explain_btn = st.button(
        "🤖 Explicar com IA",
        key=f"explain_{idx}",
        type="primary",
        use_container_width=True,
    )
with col_mode:
    if has_api_key():
        st.success(f"✅ **{mode_label}** — explicação gerada pela Claude API")
    else:
        st.info(f"💡 **{mode_label}** — adicione `ANTHROPIC_API_KEY` no `.env` para usar a Claude API")

if explain_btn:
    with st.spinner("🤖 Gerando explicação..."):
        explanation = explain_incident(inc)
    st.session_state[ai_key] = explanation

if ai_key in st.session_state:
    explanation = st.session_state[ai_key]
    st.markdown(f"""
    <div style="background:#0D1117;border:1px solid #1F2937;border-left:4px solid #00D4FF;
                border-radius:12px;padding:1.5rem;margin-top:0.5rem;line-height:1.8;">
        {explanation.replace(chr(10), '<br>').replace('**', '<b>').replace('**', '</b>')}
    </div>
    """, unsafe_allow_html=True)

# ─── Eventos brutos ───────────────────────────────────────────
raw_events = inc.get("raw_events", [])
if raw_events:
    st.markdown("---")
    st.markdown("#### 📋 Eventos Associados")
    ev_df = pd.DataFrame(raw_events)
    display_cols = [c for c in ["timestamp","source_ip","username","action","status","details"]
                    if c in ev_df.columns]
    ev_display = ev_df[display_cols].copy()

    def color_status(val):
        if str(val).lower() in ["success","true"]:  return "color:#22C55E;font-weight:600"
        if str(val).lower() in ["failure","false"]: return "color:#EF4444;font-weight:600"
        return ""

    st.dataframe(
        ev_display.style.map(color_status, subset=["status"] if "status" in ev_display.columns else []),
        use_container_width=True,
        height=min(300, 50 + len(ev_display)*35),
    )

# ─── Recomendações ────────────────────────────────────────────
st.markdown("---")
st.markdown("#### 🛡️ Recomendações de Mitigação")

recs = get_recommendations(inc["incident_type"])
PRIORITY_COLOR = {"immediate":"#EF4444","short_term":"#F97316","long_term":"#EAB308"}
PRIORITY_LABEL = {"immediate":"⚡ Imediato","short_term":"📅 Curto Prazo","long_term":"🗓️ Longo Prazo"}

for rec in recs:
    pc = PRIORITY_COLOR.get(rec["priority"], "#6B7280")
    pl = PRIORITY_LABEL.get(rec["priority"], rec["priority"])
    st.markdown(f"""
    <div style="background:#111827;border:1px solid #1F2937;border-radius:10px;
                padding:1rem 1.25rem;margin-bottom:0.6rem;display:flex;gap:1rem;align-items:flex-start;">
        <div style="min-width:110px;">
            <span style="background:{pc}22;color:{pc};border:1px solid {pc}55;
                         padding:3px 8px;border-radius:6px;font-size:0.68rem;font-weight:700;">
                {pl}
            </span>
        </div>
        <div>
            <div style="color:#F9FAFB;font-weight:600;font-size:0.88rem;">{rec['title']}</div>
            <div style="color:#9CA3AF;font-size:0.82rem;margin-top:3px;">{rec['description']}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)