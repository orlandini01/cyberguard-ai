"""04_reports.py — Geração de relatórios PDF."""
import sys, os, pickle
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
os.environ["PYTHONPATH"] = str(_ROOT)

import streamlit as st
from datetime import datetime

from src.report_generator import generate_pdf_report

st.set_page_config(page_title="Relatórios | CyberGuard AI", page_icon="📄", layout="wide")

STATE_FILE = _ROOT / "reports" / ".session_state.pkl"

# Recupera dados
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
    except Exception:
        pass

st.title("📄 Geração de Relatórios PDF")

if not scored:
    st.warning("⚠️ Nenhuma análise disponível. Vá em **Importar Logs** e execute a análise primeiro.")
    st.stop()

filename    = st.session_state.get("filename", "arquivo")
total_ev    = len(raw_df) if raw_df is not None else 0
total_inc   = len(scored)
critical    = sum(1 for s in scored if s["severity"] == "critical")
high        = sum(1 for s in scored if s["severity"] == "high")
avg_score   = round(sum(s["risk_score"] for s in scored) / total_inc, 1) if total_inc else 0

# ─── Preview da análise ───────────────────────────────────────
st.markdown("#### 📊 Análise que será incluída no relatório")
c1,c2,c3,c4,c5 = st.columns(5)
c1.metric("Arquivo",    filename)
c2.metric("Eventos",    f"{total_ev:,}")
c3.metric("Incidentes", total_inc)
c4.metric("🔴 Críticos", critical)
c5.metric("Score Médio", avg_score)

st.markdown("---")

# ─── Opções do relatório ──────────────────────────────────────
st.markdown("#### ⚙️ Configurações do Relatório")

col1, col2 = st.columns(2)
with col1:
    report_type = st.selectbox(
        "Tipo de relatório:",
        ["Completo (Executivo + Técnico)", "Executivo (Resumido)", "Técnico (Detalhado)"],
    )
with col2:
    st.markdown("<br>", unsafe_allow_html=True)
    include_recs = st.checkbox("Incluir recomendações de mitigação", value=True)

st.markdown("---")

# ─── Geração ─────────────────────────────────────────────────
st.markdown("#### 🚀 Gerar PDF")

col_btn, col_info = st.columns([2, 5])
with col_btn:
    generate = st.button("📄 Gerar Relatório PDF", type="primary", use_container_width=True)
with col_info:
    st.info("O PDF será gerado com capa, sumário executivo, incidentes detalhados e recomendações.")

if generate:
    with st.spinner("⏳ Gerando relatório PDF..."):
        try:
            analysis_data = {
                "filename":     filename,
                "total_events": total_ev,
                "scored":       scored,
            }

            pdf_bytes = generate_pdf_report(analysis_data)

            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            pdf_filename = f"cyberguard_report_{ts}.pdf"

            st.success(f"✅ Relatório gerado com sucesso! **{len(pdf_bytes)//1024} KB**")
            st.markdown("<br>", unsafe_allow_html=True)

            st.download_button(
                label="⬇️ Baixar Relatório PDF",
                data=pdf_bytes,
                file_name=pdf_filename,
                mime="application/pdf",
                use_container_width=True,
                type="primary",
            )

            st.markdown("---")
            st.markdown("#### 📋 Conteúdo do relatório gerado:")
            st.markdown(f"""
            - ✅ **Capa** com metadados e data de geração
            - ✅ **Sumário Executivo** com KPIs de segurança
            - ✅ **{min(len([s for s in scored if s['severity'] in ('critical','high')]), 10)} incidentes críticos/altos** detalhados
            - ✅ **Tabela resumo** dos demais incidentes
            - {"✅ **Recomendações** de mitigação por tipo de ameaça" if include_recs else "—"}
            - ✅ **Rodapé** com metadados e aviso de confidencialidade
            """)

        except Exception as e:
            st.error(f"❌ Erro ao gerar PDF: {e}")
            st.exception(e)