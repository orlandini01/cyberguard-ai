"""01_upload.py — Página de importação de logs."""
import sys, os
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
os.environ["PYTHONPATH"] = str(_ROOT)

import streamlit as st
import pandas as pd

from src.log_parser import parse_log_file, get_preview_stats, LogParseError

st.set_page_config(page_title="Importar Logs | CyberGuard AI", page_icon="📥", layout="wide")

# ─── CSS local ───────────────────────────────────────────────
st.markdown("""
<style>
.stat-card {
    background: #111827; border: 1px solid #1F2937;
    border-radius: 10px; padding: 1rem 1.25rem; text-align: center;
}
.stat-card .val { font-size: 1.6rem; font-weight: 700; color: #F9FAFB; }
.stat-card .lbl { font-size: 0.7rem; color: #6B7280; text-transform: uppercase;
                  letter-spacing: 0.05em; margin-top: 2px; }
</style>
""", unsafe_allow_html=True)

st.title("📥 Importar Logs de Segurança")
st.caption("Suporte a CSV, JSON e TXT · Máximo 50 MB")

# ─── Opções de origem ────────────────────────────────────────
source = st.radio(
    "Origem dos dados:",
    ["📂 Fazer upload de arquivo", "🚀 Usar dados de exemplo"],
    horizontal=True,
)

df = None
filename = None

# ── Upload de arquivo ─────────────────────────────────────────
if source == "📂 Fazer upload de arquivo":
    uploaded = st.file_uploader(
        "Selecione o arquivo de log",
        type=["csv", "json", "txt"],
        help="Formatos aceitos: CSV, JSON, TXT (syslog)",
    )

    if uploaded:
        with st.spinner("Processando arquivo..."):
            try:
                df = parse_log_file(uploaded.read(), uploaded.name)
                filename = uploaded.name
                st.success(f"✅ **{uploaded.name}** importado com sucesso!")
            except LogParseError as e:
                st.error(f"❌ **Erro ao importar arquivo:**\n\n{e}")
                with st.expander("📋 Formato esperado para CSV"):
                    st.code(
                        "timestamp,source_ip,username,action,status,details\n"
                        "2024-06-15 14:30:00,10.0.0.1,joao.silva,LOGIN,success,Login normal\n"
                        "2024-06-15 14:31:05,185.220.101.47,admin,SSH_LOGIN,failure,Senha incorreta",
                        language="text"
                    )

# ── Dados de exemplo ──────────────────────────────────────────
else:
    fmt = st.selectbox("Formato dos dados de exemplo:", ["CSV", "JSON", "TXT"])
    if st.button("🚀 Carregar dados de exemplo", type="primary"):
        sample_map = {"CSV": "sample_logs.csv", "JSON": "sample_logs.json", "TXT": "sample_logs.txt"}
        sample_path = _ROOT / "data" / sample_map[fmt]

        if not sample_path.exists():
            st.error("❌ Arquivo de exemplo não encontrado. Execute `python data/generate_samples.py` primeiro.")
        else:
            with st.spinner("Carregando dados de exemplo..."):
                try:
                    content = sample_path.read_bytes()
                    df = parse_log_file(content, sample_path.name)
                    filename = sample_path.name
                    st.success(f"✅ Dados de exemplo ({fmt}) carregados — **{len(df)} eventos**")
                except LogParseError as e:
                    st.error(f"❌ {e}")

# ─── Preview e confirmação ────────────────────────────────────
if df is not None:
    stats = get_preview_stats(df)

    st.markdown("---")
    st.markdown("#### 📊 Preview dos dados importados")

    # KPIs rápidos
    cols = st.columns(6)
    kpis = [
        ("Total de Eventos", stats["total_events"]),
        ("IPs Únicos",       stats["unique_ips"]),
        ("Usuários",         stats["unique_users"]),
        ("Ações",            stats["unique_actions"]),
        ("Sucessos",         stats["success_count"]),
        ("Falhas",           stats["failure_count"]),
    ]
    for col, (label, value) in zip(cols, kpis):
        with col:
            st.markdown(f"""
            <div class="stat-card">
                <div class="val">{value:,}</div>
                <div class="lbl">{label}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Período
    c1, c2 = st.columns(2)
    with c1:
        st.info(f"📅 **Início:** {stats['date_start'].strftime('%d/%m/%Y %H:%M:%S')}")
    with c2:
        st.info(f"📅 **Fim:** {stats['date_end'].strftime('%d/%m/%Y %H:%M:%S')}")

    # Tabela preview (primeiras 20 linhas)
    st.markdown("**Primeiras 20 linhas:**")
    preview_df = df.head(20).copy()
    preview_df["timestamp"] = preview_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    # Colorir status
    def color_status(val):
        if val == "success":
            return "color: #22C55E; font-weight: 600"
        elif val == "failure":
            return "color: #EF4444; font-weight: 600"
        return ""

    st.dataframe(
        preview_df.style.map(color_status, subset=["status"]),
        use_container_width=True,
        height=350,
    )

    st.markdown("---")
    st.markdown("#### ✅ Confirmar e iniciar análise")
    st.markdown(
        f"Arquivo **{filename}** com **{stats['total_events']} eventos** "
        f"pronto para análise. Clique no botão para processar."
    )

    if st.button("🔍 Iniciar Análise de Segurança", type="primary", use_container_width=True):
        st.session_state["raw_df"]   = df
        st.session_state["filename"] = filename
        st.session_state["analysis_data"] = None  # será preenchido na Fase 5
        st.success("✅ Dados carregados na sessão! Acesse a página **Análise** para continuar.")
        st.balloons()