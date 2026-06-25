"""
main.py — Dashboard principal do CyberGuard AI.
"""
import sys, os, pickle
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
os.environ["PYTHONPATH"] = str(_ROOT)

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from collections import Counter

st.set_page_config(
    page_title="CyberGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── CSS ─────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

section[data-testid="stSidebar"] {
    background: #0D1117; border-right: 1px solid #1F2937;
}
[data-testid="metric-container"] {
    background: #111827; border: 1px solid #1F2937;
    border-radius: 12px; padding: 1rem 1.25rem;
}
[data-testid="metric-container"] label {
    color: #6B7280 !important; font-size: 0.72rem !important;
    font-weight: 600 !important; text-transform: uppercase; letter-spacing: 0.06em;
}
[data-testid="metric-container"] [data-testid="stMetricValue"] {
    color: #F9FAFB !important; font-size: 1.9rem !important; font-weight: 700 !important;
}
.hero {
    background: linear-gradient(135deg, #0A0E1A 0%, #111827 60%, #0A0E1A 100%);
    border: 1px solid #1F2937; border-radius: 16px;
    padding: 1.75rem 2rem; margin-bottom: 1.5rem; position: relative; overflow: hidden;
}
.hero::before {
    content:''; position:absolute; top:0; left:0; right:0; height:2px;
    background: linear-gradient(90deg, transparent, #00D4FF, transparent);
}
.hero h1 { font-size:1.8rem !important; font-weight:700 !important;
           color:#F9FAFB !important; margin:0 !important; letter-spacing:-0.02em; }
.hero p  { color:#6B7280; font-size:0.88rem; margin:0.4rem 0 0 0; }
.accent  { color:#00D4FF; }
.status-badge { display:inline-flex; align-items:center; gap:6px; padding:3px 10px;
                border-radius:9999px; font-size:0.72rem; font-weight:600; }
.status-online  { background:rgba(34,197,94,0.1); color:#22C55E; border:1px solid rgba(34,197,94,0.3); }
.status-offline { background:rgba(234,179,8,0.1);  color:#EAB308; border:1px solid rgba(234,179,8,0.3); }
#MainMenu, footer { visibility:hidden; }
::-webkit-scrollbar { width:5px; }
::-webkit-scrollbar-track { background:#0D1117; }
::-webkit-scrollbar-thumb { background:#374151; border-radius:3px; }
</style>
""", unsafe_allow_html=True)

# ─── Sidebar ─────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="padding:1rem 0 1.25rem 0; border-bottom:1px solid #1F2937;">
        <div style="font-size:1.3rem;font-weight:700;color:#F9FAFB;">🛡️ CyberGuard AI</div>
        <div style="font-size:0.65rem;color:#4B5563;margin-top:3px;text-transform:uppercase;letter-spacing:0.08em;">
            Security Intelligence Platform
        </div>
    </div>""", unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    from src.utils import has_api_key
    if has_api_key():
        st.markdown('<div class="status-badge status-online">● IA Online (Claude API)</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="status-badge status-offline">● IA Offline (Templates)</div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("**NAVEGAÇÃO**")
    st.page_link("main.py",                   label="🏠  Dashboard")
    st.page_link("pages/01_upload.py",        label="📥  Importar Logs")
    st.page_link("pages/02_analysis.py",      label="🔍  Análise")
    st.page_link("pages/03_incidents.py",     label="⚠️  Incidentes")
    st.page_link("pages/04_reports.py",       label="📄  Relatórios")
    st.page_link("pages/05_history.py",       label="📋  Histórico")
    st.markdown("<br><br>", unsafe_allow_html=True)
    st.markdown("<div style='color:#374151;font-size:0.68rem;'>CyberGuard AI v1.0<br>© 2024 Pier Orlandini</div>",
                unsafe_allow_html=True)

# ─── Recupera dados ───────────────────────────────────────────
STATE_FILE = _ROOT / "reports" / ".session_state.pkl"

scored = st.session_state.get("scored_threats")
raw_df = st.session_state.get("raw_df")

if not scored and STATE_FILE.exists():
    try:
        with open(STATE_FILE, "rb") as f:
            disk = pickle.load(f)
        scored = disk["scored"]
        raw_df = disk["df"]
        st.session_state["scored_threats"] = scored
        st.session_state["raw_df"]         = raw_df
        st.session_state["filename"]       = disk["filename"]
        st.session_state["analysis_data"]  = scored
    except Exception:
        pass

# ─── Hero ────────────────────────────────────────────────────
filename = st.session_state.get("filename", "")
st.markdown(f"""
<div class="hero">
    <h1>🛡️ CyberGuard <span class="accent">AI</span></h1>
    <p>Plataforma inteligente de monitoramento e análise de segurança · MVP v1.0
    {"· <b>" + filename + "</b>" if filename else ""}
    </p>
</div>
""", unsafe_allow_html=True)

# ─── Sem dados ───────────────────────────────────────────────
if not scored or raw_df is None:
    c1, c2, c3 = st.columns(3)
    c1.info("**📥 Passo 1**\n\nVá em **Importar Logs** e carregue um arquivo CSV, JSON ou TXT.")
    c2.info("**🔍 Passo 2**\n\nClique em **Executar Análise** — o motor detecta 6 tipos de ameaça.")
    c3.info("**📊 Passo 3**\n\nVolte ao Dashboard para ver os gráficos completos.")
    st.markdown("---")
    if st.button("📥 Ir para Importar Logs", type="primary"):
        st.switch_page("pages/01_upload.py")
    st.stop()

# ════════════════════════════════════════════════════════════
# DASHBOARD COM DADOS
# ════════════════════════════════════════════════════════════

total     = len(scored)
critical  = sum(1 for s in scored if s["severity"] == "critical")
high      = sum(1 for s in scored if s["severity"] == "high")
medium    = sum(1 for s in scored if s["severity"] == "medium")
low       = sum(1 for s in scored if s["severity"] == "low")
avg_score = round(sum(s["risk_score"] for s in scored) / total, 1) if total else 0
total_ev  = len(raw_df)
failures  = int((raw_df["status"] == "failure").sum())
unique_ips = raw_df["source_ip"].nunique()

# ─── KPIs ────────────────────────────────────────────────────
st.markdown("#### 📊 Resumo Executivo")
c1,c2,c3,c4,c5,c6,c7 = st.columns(7)
c1.metric("Total Eventos",   f"{total_ev:,}")
c2.metric("Falhas Auth",     f"{failures:,}")
c3.metric("IPs Distintos",   f"{unique_ips:,}")
c4.metric("Incidentes",      total)
c5.metric("🔴 Críticos",     critical)
c6.metric("🟠 Altos",        high)
c7.metric("Score Médio",     avg_score)

st.markdown("<br>", unsafe_allow_html=True)

# ─── Linha 1: Pizza + Barras de tipo ─────────────────────────
col1, col2 = st.columns(2)

with col1:
    sev_counts = {"Crítico": critical, "Alto": high, "Médio": medium, "Baixo": low}
    sev_colors = ["#EF4444","#F97316","#EAB308","#22C55E"]
    fig_pie = go.Figure(go.Pie(
        labels=list(sev_counts.keys()),
        values=list(sev_counts.values()),
        marker_colors=sev_colors,
        hole=0.55,
        textinfo="label+percent",
        textfont_size=12,
    ))
    fig_pie.update_layout(
        title="Distribuição por Severidade",
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#D1D5DB", showlegend=False,
        margin=dict(t=40,b=10,l=10,r=10), height=300,
    )
    fig_pie.add_annotation(text=f"<b>{total}</b><br>incidentes",
                           x=0.5, y=0.5, showarrow=False,
                           font=dict(size=14, color="#F9FAFB"))
    st.plotly_chart(fig_pie, use_container_width=True)

with col2:
    type_counts = Counter(s["incident_type"] for s in scored)
    labels_pt = {
        "BRUTE_FORCE":           "Força Bruta",
        "SUCCESS_AFTER_FAILURE": "Login Após Falhas",
        "OFF_HOURS_ACCESS":      "Fora do Horário",
        "SUSPICIOUS_IP":         "IP Suspeito",
        "USER_ENUMERATION":      "Enumeração",
        "PRIVILEGED_ACCESS":     "Acesso Privilegiado",
    }
    tc_df = pd.DataFrame([
        {"Tipo": labels_pt.get(k, k), "Incidentes": v}
        for k, v in sorted(type_counts.items(), key=lambda x: -x[1])
    ])
    fig_bar = px.bar(tc_df, x="Incidentes", y="Tipo", orientation="h",
                     color="Incidentes", color_continuous_scale=["#1F2937","#EF4444"],
                     title="Incidentes por Tipo de Ameaça")
    fig_bar.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#D1D5DB", showlegend=False, coloraxis_showscale=False,
        margin=dict(t=40,b=10,l=10,r=10), height=300,
        yaxis=dict(gridcolor="#1F2937"), xaxis=dict(gridcolor="#1F2937"),
    )
    st.plotly_chart(fig_bar, use_container_width=True)

# ─── Linha 2: Timeline de eventos ────────────────────────────
st.markdown("#### 📅 Linha do Tempo de Eventos")

timeline_df = raw_df.copy()
timeline_df["hour"] = timeline_df["timestamp"].dt.floor("h")
timeline_grouped = (timeline_df.groupby(["hour","status"])
                    .size().reset_index(name="count"))

fig_time = px.bar(timeline_grouped, x="hour", y="count", color="status",
                  color_discrete_map={"success":"#22C55E","failure":"#EF4444"},
                  barmode="stack", title="Eventos por Hora (empilhado por status)")
fig_time.update_layout(
    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
    font_color="#D1D5DB", legend_title="Status",
    xaxis=dict(gridcolor="#1F2937", title=""),
    yaxis=dict(gridcolor="#1F2937", title="Eventos"),
    margin=dict(t=40,b=10,l=10,r=10), height=280,
)
st.plotly_chart(fig_time, use_container_width=True)

# ─── Linha 3: Top IPs + Top usuários ─────────────────────────
col3, col4 = st.columns(2)

with col3:
    top_ips = (raw_df[raw_df["status"]=="failure"]
               .groupby("source_ip").size()
               .sort_values(ascending=False).head(10).reset_index())
    top_ips.columns = ["IP", "Falhas"]
    fig_ips = px.bar(top_ips, x="Falhas", y="IP", orientation="h",
                     title="🌐 Top 10 IPs com Mais Falhas",
                     color="Falhas", color_continuous_scale=["#374151","#EF4444"])
    fig_ips.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#D1D5DB", coloraxis_showscale=False, showlegend=False,
        margin=dict(t=40,b=10,l=10,r=10), height=320,
        yaxis=dict(gridcolor="#1F2937"), xaxis=dict(gridcolor="#1F2937"),
    )
    st.plotly_chart(fig_ips, use_container_width=True)

with col4:
    top_users = (raw_df[raw_df["status"]=="failure"]
                 .groupby("username").size()
                 .sort_values(ascending=False).head(10).reset_index())
    top_users.columns = ["Usuário", "Falhas"]
    fig_users = px.bar(top_users, x="Falhas", y="Usuário", orientation="h",
                       title="👤 Top 10 Usuários Mais Atacados",
                       color="Falhas", color_continuous_scale=["#374151","#F97316"])
    fig_users.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#D1D5DB", coloraxis_showscale=False, showlegend=False,
        margin=dict(t=40,b=10,l=10,r=10), height=320,
        yaxis=dict(gridcolor="#1F2937"), xaxis=dict(gridcolor="#1F2937"),
    )
    st.plotly_chart(fig_users, use_container_width=True)

# ─── Linha 4: Evolução do risco + Mapa de calor horário ──────
col5, col6 = st.columns(2)

with col5:
    # Score dos incidentes ordenados por data
    risk_df = pd.DataFrame([{
        "data":  s["first_seen"],
        "score": s["risk_score"],
        "tipo":  labels_pt.get(s["incident_type"], s["incident_type"]),
        "sev":   s["severity"],
    } for s in scored]).sort_values("data")

    fig_risk = px.scatter(risk_df, x="data", y="score", color="sev",
                          color_discrete_map={"critical":"#EF4444","high":"#F97316",
                                              "medium":"#EAB308","low":"#22C55E"},
                          hover_data=["tipo"], title="📈 Evolução do Score de Risco",
                          size=[8]*len(risk_df))
    fig_risk.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#D1D5DB", legend_title="Severidade",
        xaxis=dict(gridcolor="#1F2937", title=""),
        yaxis=dict(gridcolor="#1F2937", title="Score", range=[0,105]),
        margin=dict(t=40,b=10,l=10,r=10), height=300,
    )
    fig_risk.add_hline(y=75, line_dash="dash", line_color="#EF4444",
                       annotation_text="Crítico (75)", annotation_font_color="#EF4444")
    fig_risk.add_hline(y=50, line_dash="dash", line_color="#F97316",
                       annotation_text="Alto (50)", annotation_font_color="#F97316")
    st.plotly_chart(fig_risk, use_container_width=True)

with col6:
    # Heatmap: dia da semana × hora do dia
    hm_df = raw_df.copy()
    hm_df["hora"]    = hm_df["timestamp"].dt.hour
    hm_df["weekday"] = hm_df["timestamp"].dt.day_name()
    days_order = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
    days_pt    = {"Monday":"Seg","Tuesday":"Ter","Wednesday":"Qua",
                  "Thursday":"Qui","Friday":"Sex","Saturday":"Sáb","Sunday":"Dom"}
    hm_pivot = (hm_df.groupby(["weekday","hora"]).size()
                .unstack(fill_value=0)
                .reindex([d for d in days_order if d in hm_df["weekday"].unique()]))
    hm_pivot.index = [days_pt.get(d, d) for d in hm_pivot.index]

    fig_hm = px.imshow(hm_pivot, color_continuous_scale=["#0D1117","#00D4FF","#EF4444"],
                       title="🔥 Mapa de Calor: Atividade por Hora/Dia",
                       labels={"x":"Hora","y":"Dia","color":"Eventos"})
    fig_hm.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#D1D5DB", margin=dict(t=40,b=10,l=10,r=10), height=300,
    )
    st.plotly_chart(fig_hm, use_container_width=True)

# ─── Top incidentes críticos ──────────────────────────────────
st.markdown("---")
st.markdown("#### 🔴 Top Incidentes Críticos")

crits = [s for s in scored if s["severity"] == "critical"][:5]
if crits:
    for inc in crits:
        label = labels_pt.get(inc["incident_type"], inc["incident_type"])
        ts    = inc["first_seen"].strftime("%d/%m/%Y %H:%M")
        st.markdown(f"""
        <div style="background:#111827;border:1px solid #1F2937;border-left:4px solid #EF4444;
                    border-radius:10px;padding:0.9rem 1.2rem;margin-bottom:0.5rem;">
            <div style="display:flex;align-items:center;gap:10px;">
                <span style="color:#EF4444;font-weight:700;font-size:0.85rem;">🔴 {label}</span>
                <span style="background:#EF444422;color:#EF4444;border:1px solid #EF444455;
                             padding:2px 8px;border-radius:9999px;font-size:0.7rem;font-weight:700;">
                    CRITICAL · {inc['risk_score']}
                </span>
            </div>
            <div style="color:#9CA3AF;font-size:0.82rem;margin-top:5px;">{inc['description']}</div>
            <div style="color:#4B5563;font-size:0.72rem;margin-top:4px;">
                🌐 {inc['source_ip']} &nbsp;|&nbsp; 👤 {inc['target_user']} &nbsp;|&nbsp; 📅 {ts}
            </div>
        </div>
        """, unsafe_allow_html=True)
else:
    st.success("✅ Nenhum incidente crítico detectado.")