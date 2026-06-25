"""
report_generator.py — Geração de relatórios PDF profissionais com ReportLab.
"""

from pathlib import Path
from datetime import datetime
from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from loguru import logger

# ─── Paleta de cores ─────────────────────────────────────────
C_BG        = colors.HexColor("#0A0E1A")
C_CARD      = colors.HexColor("#111827")
C_BORDER    = colors.HexColor("#1F2937")
C_TEXT      = colors.HexColor("#F9FAFB")
C_MUTED     = colors.HexColor("#6B7280")
C_ACCENT    = colors.HexColor("#00D4FF")
C_CRITICAL  = colors.HexColor("#EF4444")
C_HIGH      = colors.HexColor("#F97316")
C_MEDIUM    = colors.HexColor("#EAB308")
C_LOW       = colors.HexColor("#22C55E")
C_WHITE     = colors.white
C_DARK      = colors.HexColor("#1F2937")

SEV_COLORS = {
    "critical": C_CRITICAL, "high": C_HIGH,
    "medium":   C_MEDIUM,   "low":  C_LOW,
}
SEV_LABELS = {
    "critical": "CRÍTICO", "high": "ALTO",
    "medium":   "MÉDIO",   "low":  "BAIXO",
}
INCIDENT_LABELS = {
    "BRUTE_FORCE":           "Ataque de Força Bruta",
    "SUCCESS_AFTER_FAILURE": "Login Após Múltiplas Falhas",
    "OFF_HOURS_ACCESS":      "Acesso em Horário Incomum",
    "SUSPICIOUS_IP":         "Comportamento Suspeito de IP",
    "USER_ENUMERATION":      "Enumeração de Usuários",
    "PRIVILEGED_ACCESS":     "Acesso Privilegiado Suspeito",
}


def generate_pdf_report(analysis_data: dict, output_path: Path | None = None) -> bytes:
    """
    Gera relatório PDF completo e retorna os bytes do PDF.

    Args:
        analysis_data: Dict com keys: filename, total_events, scored, raw_df (opcional)
        output_path: Se fornecido, salva o PDF neste caminho também

    Returns:
        Bytes do PDF gerado
    """
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm,  bottomMargin=2*cm,
        title="CyberGuard AI — Relatório de Segurança",
        author="CyberGuard AI v1.0",
    )

    styles = _build_styles()
    story  = []

    scored   = analysis_data.get("scored", [])
    filename = analysis_data.get("filename", "arquivo")
    total_ev = analysis_data.get("total_events", 0)
    gen_at   = datetime.now().strftime("%d/%m/%Y às %H:%M:%S")

    # Métricas globais
    total    = len(scored)
    critical = sum(1 for s in scored if s["severity"] == "critical")
    high     = sum(1 for s in scored if s["severity"] == "high")
    medium   = sum(1 for s in scored if s["severity"] == "medium")
    low      = sum(1 for s in scored if s["severity"] == "low")
    avg_sc   = round(sum(s["risk_score"] for s in scored) / total, 1) if total else 0

    # ── CAPA ──────────────────────────────────────────────────
    story += _build_cover(styles, filename, gen_at, total, critical, high, avg_sc)
    story.append(PageBreak())

    # ── SUMÁRIO EXECUTIVO ────────────────────────────────────
    story += _build_executive_summary(
        styles, filename, total_ev, total, critical, high, medium, low, avg_sc, gen_at
    )
    story.append(Spacer(1, 0.5*cm))

    # ── INCIDENTES CRÍTICOS E ALTOS ───────────────────────────
    story.append(Paragraph("2. Incidentes Detectados", styles["section"]))
    story.append(Spacer(1, 0.3*cm))

    priority_incidents = [s for s in scored if s["severity"] in ("critical", "high")]
    other_incidents    = [s for s in scored if s["severity"] in ("medium", "low")]

    if priority_incidents:
        story.append(Paragraph("2.1 Incidentes Críticos e Altos", styles["subsection"]))
        story.append(Spacer(1, 0.2*cm))
        for inc in priority_incidents[:10]:
            story += _build_incident_block(styles, inc)
            story.append(Spacer(1, 0.3*cm))

    if other_incidents:
        story.append(Paragraph("2.2 Resumo — Incidentes Médios e Baixos", styles["subsection"]))
        story.append(Spacer(1, 0.2*cm))
        story += _build_incidents_table(styles, other_incidents[:20])
        story.append(Spacer(1, 0.5*cm))

    # ── RECOMENDAÇÕES ─────────────────────────────────────────
    story.append(Paragraph("3. Recomendações de Ação", styles["section"]))
    story.append(Spacer(1, 0.3*cm))
    story += _build_recommendations(styles, scored)

    # ── RODAPÉ / METADADOS ────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        f"Relatório gerado por <b>CyberGuard AI v1.0</b> em {gen_at} · "
        f"Arquivo analisado: {filename} · "
        f"Este documento é confidencial e destinado apenas ao receptor autorizado.",
        styles["footer"]
    ))

    doc.build(story)

    pdf_bytes = buffer.getvalue()
    buffer.close()

    if output_path:
        output_path.write_bytes(pdf_bytes)
        logger.info(f"PDF salvo em {output_path} ({len(pdf_bytes)//1024} KB)")

    return pdf_bytes


# ─── Builders de seções ───────────────────────────────────────

def _build_cover(styles, filename, gen_at, total, critical, high, avg_sc):
    elements = []
    elements.append(Spacer(1, 2*cm))

    # Título
    elements.append(Paragraph("🛡️ CyberGuard AI", styles["cover_title"]))
    elements.append(Spacer(1, 0.4*cm))
    elements.append(Paragraph("Relatório de Análise de Segurança", styles["cover_subtitle"]))
    elements.append(Spacer(1, 0.2*cm))
    elements.append(HRFlowable(width="60%", thickness=2, color=C_ACCENT, hAlign="CENTER"))
    elements.append(Spacer(1, 2*cm))

    # Tabela de metadados da capa
    meta_data = [
        ["Arquivo Analisado", filename],
        ["Data de Geração",   gen_at],
        ["Total de Incidentes", str(total)],
        ["Incidentes Críticos", str(critical)],
        ["Incidentes Altos",    str(high)],
        ["Score Médio de Risco", str(avg_sc)],
    ]
    meta_table = Table(meta_data, colWidths=[6*cm, 10*cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (0,-1), C_DARK),
        ("BACKGROUND",  (1,0), (1,-1), C_CARD),
        ("TEXTCOLOR",   (0,0), (0,-1), C_ACCENT),
        ("TEXTCOLOR",   (1,0), (1,-1), C_TEXT),
        ("FONTNAME",    (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 10),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_CARD, C_BG]),
        ("GRID",        (0,0), (-1,-1), 0.5, C_BORDER),
        ("PADDING",     (0,0), (-1,-1), 10),
        ("ALIGN",       (0,0), (-1,-1), "LEFT"),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 3*cm))

    # Aviso de confidencialidade
    elements.append(Paragraph(
        "⚠️  DOCUMENTO CONFIDENCIAL — USO INTERNO",
        styles["confidential"]
    ))
    return elements


def _build_executive_summary(styles, filename, total_ev, total, critical, high, medium, low, avg_sc, gen_at):
    elements = []
    elements.append(Paragraph("1. Sumário Executivo", styles["section"]))
    elements.append(Spacer(1, 0.3*cm))

    # Texto introdutório
    risk_level = "CRÍTICO" if critical > 0 else "ALTO" if high > 0 else "MÉDIO"
    elements.append(Paragraph(
        f"A análise do arquivo <b>{filename}</b> processou <b>{total_ev:,} eventos</b> de log de segurança "
        f"e identificou <b>{total} incidente(s)</b> que requerem atenção. "
        f"O nível de risco geral da infraestrutura analisada é classificado como <b>{risk_level}</b>, "
        f"com score médio de <b>{avg_sc}/100</b>.",
        styles["body"]
    ))
    elements.append(Spacer(1, 0.4*cm))

    # Tabela de KPIs
    kpi_data = [
        ["Métrica", "Valor", "Status"],
        ["Total de Eventos Analisados", f"{total_ev:,}", "—"],
        ["Total de Incidentes Detectados", str(total), "⚠️" if total > 0 else "✅"],
        ["Incidentes Críticos (score ≥ 75)", str(critical), "🔴" if critical > 0 else "✅"],
        ["Incidentes Altos (score 50–74)",   str(high),     "🟠" if high > 0 else "✅"],
        ["Incidentes Médios (score 25–49)",  str(medium),   "🟡" if medium > 0 else "✅"],
        ["Incidentes Baixos (score 0–24)",   str(low),      "🟢"],
        ["Score Médio de Risco",             f"{avg_sc}/100", "🔴" if avg_sc >= 75 else "🟠"],
    ]
    kpi_table = Table(kpi_data, colWidths=[8*cm, 4*cm, 3*cm])
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), C_ACCENT),
        ("TEXTCOLOR",   (0,0), (-1,0), C_BG),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_CARD, C_BG]),
        ("TEXTCOLOR",   (0,1), (-1,-1), C_TEXT),
        ("GRID",        (0,0), (-1,-1), 0.5, C_BORDER),
        ("PADDING",     (0,0), (-1,-1), 8),
        ("ALIGN",       (1,0), (2,-1), "CENTER"),
        ("ALIGN",       (0,0), (0,-1), "LEFT"),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
    ]))
    elements.append(kpi_table)
    elements.append(Spacer(1, 0.5*cm))
    return elements


def _build_incident_block(styles, inc):
    elements = []
    sev_color = SEV_COLORS.get(inc["severity"], C_MUTED)
    sev_label = SEV_LABELS.get(inc["severity"], inc["severity"].upper())
    inc_label = INCIDENT_LABELS.get(inc["incident_type"], inc["incident_type"])
    ts_first  = inc["first_seen"].strftime("%d/%m/%Y %H:%M") if hasattr(inc["first_seen"], "strftime") else str(inc["first_seen"])
    ts_last   = inc["last_seen"].strftime("%d/%m/%Y %H:%M")  if hasattr(inc["last_seen"],  "strftime") else str(inc["last_seen"])

    block_data = [
        [Paragraph(f'<b>{inc_label}</b>', styles["incident_title"]),
         Paragraph(f'<font color="{sev_color.hexval() if hasattr(sev_color,"hexval") else "#EF4444"}"><b>{sev_label} · {inc["risk_score"]}</b></font>',
                   styles["incident_badge"])],
        [Paragraph(inc["description"], styles["body_small"]), ""],
        [Paragraph(f'IP: <b>{inc["source_ip"]}</b> | Usuário: <b>{inc["target_user"]}</b> | '
                   f'Eventos: <b>{inc["event_count"]}</b> | '
                   f'{ts_first} → {ts_last}', styles["incident_meta"]), ""],
    ]

    block_table = Table(block_data, colWidths=[12*cm, 4*cm])
    block_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,-1), C_CARD),
        ("LINECOLOR",   (0,0), (0,-1), sev_color),
        ("LINEWIDTH",   (0,0), (0,-1), 3),
        ("GRID",        (0,0), (-1,-1), 0.3, C_BORDER),
        ("PADDING",     (0,0), (-1,-1), 8),
        ("VALIGN",      (0,0), (-1,-1), "TOP"),
        ("SPAN",        (0,1), (1,1)),
        ("SPAN",        (0,2), (1,2)),
    ]))
    elements.append(KeepTogether([block_table]))
    return elements


def _build_incidents_table(styles, incidents):
    elements = []
    headers = ["Tipo", "IP Origem", "Usuário", "Score", "Severidade", "Eventos"]
    rows = [headers]
    for inc in incidents:
        rows.append([
            INCIDENT_LABELS.get(inc["incident_type"], inc["incident_type"])[:30],
            inc["source_ip"],
            str(inc["target_user"])[:20],
            str(inc["risk_score"]),
            SEV_LABELS.get(inc["severity"], inc["severity"].upper()),
            str(inc["event_count"]),
        ])
    table = Table(rows, colWidths=[5*cm, 3.5*cm, 3*cm, 1.5*cm, 2.5*cm, 1.5*cm])
    table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), C_DARK),
        ("TEXTCOLOR",   (0,0), (-1,0), C_ACCENT),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_CARD, C_BG]),
        ("TEXTCOLOR",   (0,1), (-1,-1), C_TEXT),
        ("GRID",        (0,0), (-1,-1), 0.3, C_BORDER),
        ("PADDING",     (0,0), (-1,-1), 6),
        ("ALIGN",       (3,0), (5,-1), "CENTER"),
    ]))
    elements.append(table)
    return elements


def _build_recommendations(styles, scored):
    elements = []
    seen_types = set()
    recs = {
        "BRUTE_FORCE": [
            ("⚡ Imediato", "Bloquear IP atacante no firewall", "Adicione o IP à lista de bloqueio permanente."),
            ("📅 Curto Prazo", "Implementar bloqueio automático", "Configure fail2ban ou similar: bloqueio após 5 tentativas."),
            ("🗓️ Longo Prazo", "Implementar MFA obrigatório", "Autenticação multifator elimina ataques de força bruta."),
        ],
        "SUCCESS_AFTER_FAILURE": [
            ("⚡ Imediato", "Revogar sessão e resetar senha", "Force logout imediato e redefina a senha do usuário comprometido."),
            ("⚡ Imediato", "Auditar ações pós-login", "Revise tudo que o atacante fez após o login bem-sucedido."),
            ("📅 Curto Prazo", "Ativar alertas de login suspeito", "Configure notificações em tempo real para padrão falha→sucesso."),
        ],
        "USER_ENUMERATION": [
            ("⚡ Imediato", "Bloquear IP enumerador", "IP testou sistematicamente dezenas de usernames — bloqueio imediato."),
            ("📅 Curto Prazo", "Padronizar mensagens de erro", "Retorne sempre 'credenciais inválidas', nunca diferencie user/senha."),
            ("📅 Curto Prazo", "Implementar CAPTCHA progressivo", "Exija CAPTCHA após 3 tentativas falhas do mesmo IP."),
        ],
        "SUSPICIOUS_IP": [
            ("⚡ Imediato", "Investigar e bloquear IP", "IP realizou acesso horizontal a múltiplas contas — bloqueio preventivo."),
            ("📅 Curto Prazo", "Integrar threat intelligence", "Use feeds de IPs maliciosos para bloqueio automático e proativo."),
        ],
        "OFF_HOURS_ACCESS": [
            ("📅 Curto Prazo", "Implementar política de horário", "Restrinja logins fora do horário comercial para usuários comuns."),
            ("📅 Curto Prazo", "Configurar alertas de horário", "Notifique equipe de segurança para acessos noturnos ou de fim de semana."),
        ],
        "PRIVILEGED_ACCESS": [
            ("⚡ Imediato", "Verificar legitimidade do acesso", "Confirme com o responsável se o acesso privilegiado era esperado."),
            ("📅 Curto Prazo", "Implementar PAM (Privileged Access Management)", "Controle e audite todo acesso a contas privilegiadas."),
            ("🗓️ Longo Prazo", "Adotar princípio do mínimo privilégio", "Remova privilégios desnecessários e use contas de serviço dedicadas."),
        ],
    }

    rec_rows = [["Prioridade", "Ação", "Descrição"]]
    for inc in scored:
        itype = inc["incident_type"]
        if itype in seen_types:
            continue
        seen_types.add(itype)
        for priority, action, desc in recs.get(itype, []):
            rec_rows.append([priority, action, desc])

    if len(rec_rows) == 1:
        elements.append(Paragraph("Nenhuma recomendação específica disponível.", styles["body"]))
        return elements

    table = Table(rec_rows, colWidths=[3*cm, 5.5*cm, 8.5*cm])
    table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), C_DARK),
        ("TEXTCOLOR",   (0,0), (-1,0), C_ACCENT),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_CARD, C_BG]),
        ("TEXTCOLOR",   (0,1), (-1,-1), C_TEXT),
        ("GRID",        (0,0), (-1,-1), 0.3, C_BORDER),
        ("PADDING",     (0,0), (-1,-1), 7),
        ("VALIGN",      (0,0), (-1,-1), "TOP"),
        ("ALIGN",       (0,0), (0,-1), "CENTER"),
    ]))
    elements.append(table)
    return elements


# ─── Estilos ──────────────────────────────────────────────────

def _build_styles():
    base = getSampleStyleSheet()
    def s(name, **kwargs):
        return ParagraphStyle(name, **kwargs)

    return {
        "cover_title": s("cover_title",
            fontSize=28, textColor=C_TEXT, alignment=TA_CENTER,
            fontName="Helvetica-Bold", spaceAfter=8),
        "cover_subtitle": s("cover_subtitle",
            fontSize=14, textColor=C_ACCENT, alignment=TA_CENTER,
            fontName="Helvetica", spaceAfter=4),
        "confidential": s("confidential",
            fontSize=9, textColor=C_CRITICAL, alignment=TA_CENTER,
            fontName="Helvetica-Bold"),
        "section": s("section",
            fontSize=14, textColor=C_ACCENT, fontName="Helvetica-Bold",
            spaceBefore=16, spaceAfter=6,
            borderPadding=(0,0,4,0)),
        "subsection": s("subsection",
            fontSize=11, textColor=C_TEXT, fontName="Helvetica-Bold",
            spaceBefore=10, spaceAfter=4),
        "body": s("body",
            fontSize=9, textColor=C_TEXT, fontName="Helvetica",
            leading=14, spaceAfter=4),
        "body_small": s("body_small",
            fontSize=8, textColor=colors.HexColor("#9CA3AF"),
            fontName="Helvetica", leading=12),
        "incident_title": s("incident_title",
            fontSize=10, textColor=C_TEXT, fontName="Helvetica-Bold"),
        "incident_badge": s("incident_badge",
            fontSize=9, fontName="Helvetica-Bold", alignment=TA_RIGHT),
        "incident_meta": s("incident_meta",
            fontSize=7.5, textColor=C_MUTED, fontName="Helvetica"),
        "footer": s("footer",
            fontSize=7, textColor=C_MUTED, fontName="Helvetica",
            alignment=TA_CENTER, leading=10),
    }