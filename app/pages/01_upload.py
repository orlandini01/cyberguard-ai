"""01_upload.py — Importação e análise de logs."""
import sys, os, pickle
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
os.environ["PYTHONPATH"] = str(_ROOT)

import streamlit as st
import pandas as pd

from src.log_parser import parse_log_file, get_preview_stats, LogParseError
from src.threat_detector import detect_all_threats
from src.risk_engine import score_all_threats
from src.database import init_db, save_analysis

# Garante que o banco existe
init_db()

st.set_page_config(page_title="Importar Logs | CyberGuard AI", page_icon="📥", layout="wide")

STATE_FILE = _ROOT / "reports" / ".session_state.pkl"

def save_to_disk(df, filename, scored):
    STATE_FILE.parent.mkdir(exist_ok=True)
    with open(STATE_FILE, "wb") as f:
        pickle.dump({"df": df, "filename": filename, "scored": scored}, f)

def load_from_disk():
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "rb") as f:
                return pickle.load(f)
        except Exception:
            return None
    return None

# ─── Inicializa session_state ─────────────────────────────────
if "upload_df" not in st.session_state:
    st.session_state["upload_df"] = None
if "upload_filename" not in st.session_state:
    st.session_state["upload_filename"] = None

disk = load_from_disk()

st.title("📥 Importar Logs de Segurança")
st.caption("Suporte a CSV, JSON e TXT · Máximo 50 MB")

source = st.radio("Origem dos dados:",
    ["📂 Fazer upload de arquivo", "🚀 Usar dados de exemplo"],
    horizontal=True)

# ── Upload ────────────────────────────────────────────────────
if source == "📂 Fazer upload de arquivo":
    uploaded = st.file_uploader("Selecione o arquivo", type=["csv","json","txt"])
    if uploaded:
        try:
            df_new = parse_log_file(uploaded.read(), uploaded.name)
            st.session_state["upload_df"]       = df_new
            st.session_state["upload_filename"] = uploaded.name
            st.success(f"✅ {uploaded.name} — {len(df_new):,} eventos")
        except LogParseError as e:
            st.error(f"❌ {e}")

# ── Dados de exemplo ──────────────────────────────────────────
else:
    fmt = st.selectbox("Formato:", ["CSV", "JSON", "TXT"])
    if st.button("🚀 Carregar dados de exemplo", type="primary"):
        sample_map = {"CSV": "sample_logs.csv", "JSON": "sample_logs.json", "TXT": "sample_logs.txt"}
        path = _ROOT / "data" / sample_map[fmt]
        if not path.exists():
            st.error("❌ Arquivo não encontrado. Execute `python data/generate_samples.py`")
        else:
            try:
                df_new = parse_log_file(path.read_bytes(), path.name)
                st.session_state["upload_df"]       = df_new
                st.session_state["upload_filename"] = path.name
                st.success(f"✅ {len(df_new):,} eventos carregados!")
            except LogParseError as e:
                st.error(f"❌ {e}")

# ─── Preview ──────────────────────────────────────────────────
df       = st.session_state.get("upload_df")
filename = st.session_state.get("upload_filename")

if df is not None:
    stats = get_preview_stats(df)
    st.markdown("---")
    st.markdown("#### 📊 Preview")

    c1,c2,c3,c4,c5,c6 = st.columns(6)
    for col, (lbl, val) in zip(
        [c1,c2,c3,c4,c5,c6],
        [("Eventos", stats["total_events"]), ("IPs", stats["unique_ips"]),
         ("Usuários", stats["unique_users"]), ("Ações", stats["unique_actions"]),
         ("Sucessos", stats["success_count"]), ("Falhas", stats["failure_count"])]
    ):
        col.metric(lbl, f"{val:,}")

    st.markdown("<br>", unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    c1.info(f"📅 Início: {stats['date_start'].strftime('%d/%m/%Y %H:%M')}")
    c2.info(f"📅 Fim:    {stats['date_end'].strftime('%d/%m/%Y %H:%M')}")

    prev = df.head(15).copy()
    prev["timestamp"] = prev["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    st.dataframe(prev, use_container_width=True, height=280)

    st.markdown("---")
    st.markdown("#### ⚡ Analisar este arquivo")

    if st.button("🔍 Executar Análise de Segurança", type="primary", use_container_width=True):
        with st.spinner("🔍 Detectando ameaças..."):
            threats = detect_all_threats(df)
        with st.spinner("📊 Calculando scores de risco..."):
            scored = score_all_threats(threats)

        # Salva na sessão
        st.session_state["raw_df"]         = df
        st.session_state["filename"]       = filename
        st.session_state["scored_threats"] = scored
        st.session_state["analysis_data"]  = scored

        # Salva no disco (persistência entre páginas)
        save_to_disk(df, filename, scored)

        # Salva no banco de dados
        try:
            analysis_id = save_analysis(filename, len(df), scored)
            st.session_state["analysis_id"] = analysis_id
        except Exception as e:
            st.warning(f"⚠️ Não foi possível salvar no banco: {e}")

        n_crit = sum(1 for s in scored if s["severity"] == "critical")
        n_high = sum(1 for s in scored if s["severity"] == "high")
        st.success(f"✅ {len(scored)} incidentes detectados — {n_crit} críticos · {n_high} altos")
        st.info("👉 Agora clique em **Análise** na sidebar para ver os resultados detalhados.")
        st.balloons()

elif disk:
    st.markdown("---")
    st.info(f"💾 Análise anterior: **{disk['filename']}** · {len(disk['scored'])} incidentes")
    if st.button("♻️ Restaurar análise anterior", use_container_width=True):
        st.session_state["upload_df"]       = disk["df"]
        st.session_state["upload_filename"] = disk["filename"]
        st.session_state["raw_df"]          = disk["df"]
        st.session_state["filename"]        = disk["filename"]
        st.session_state["scored_threats"]  = disk["scored"]
        st.session_state["analysis_data"]   = disk["scored"]
        st.rerun()

# ─── Status da sessão ─────────────────────────────────────────
st.markdown("---")
if st.session_state.get("scored_threats"):
    n  = len(st.session_state["scored_threats"])
    fn = st.session_state.get("filename", "")
    st.success(f"✅ Sessão ativa: **{fn}** · {n} incidentes prontos")
else:
    st.info("ℹ️ Nenhuma análise ativa na sessão.")