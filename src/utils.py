"""
utils.py — Funções utilitárias compartilhadas do CyberGuard AI.
"""

import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from loguru import logger

# Carrega variáveis de ambiente do .env (se existir)
load_dotenv()


# ─── Configuração de logging ─────────────────────────────────

def setup_logger() -> None:
    """Configura o logger da aplicação com formato estruturado."""
    logger.remove()
    logger.add(
        "logs/cyberguard_{time:YYYY-MM-DD}.log",
        rotation="1 day",
        retention="7 days",
        level="INFO",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {module}:{function} | {message}",
        enqueue=True,
    )
    logger.add(
        lambda msg: None,  # console handler silencioso (Streamlit captura stdout)
        level="DEBUG",
        format="{level} | {message}",
    )


# ─── Variáveis de ambiente ───────────────────────────────────

def get_env(key: str, default: str = "") -> str:
    """Lê uma variável de ambiente com valor padrão."""
    return os.getenv(key, default)


def get_env_int(key: str, default: int = 0) -> int:
    """Lê uma variável de ambiente como inteiro."""
    try:
        return int(os.getenv(key, str(default)))
    except (ValueError, TypeError):
        return default


def get_env_bool(key: str, default: bool = False) -> bool:
    """Lê uma variável de ambiente como booleano."""
    val = os.getenv(key, str(default)).lower()
    return val in ("true", "1", "yes")


# ─── Detecção de API key ─────────────────────────────────────

def has_api_key() -> bool:
    """Verifica se a ANTHROPIC_API_KEY está configurada."""
    key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    return bool(key and key != "your_key_here")


# ─── Utilitários de tempo ────────────────────────────────────

def is_off_hours(hour: int) -> bool:
    """
    Verifica se uma hora é considerada fora do horário comercial.

    Args:
        hour: Hora do dia (0-23)

    Returns:
        True se for horário suspeito (padrão: antes das 7h ou após as 22h)
    """
    off_start = get_env_int("OFF_HOURS_START", 22)
    off_end = get_env_int("OFF_HOURS_END", 7)
    return hour >= off_start or hour < off_end


def is_weekend(dt: datetime) -> bool:
    """Verifica se um datetime cai num fim de semana."""
    return dt.weekday() >= 5  # 5=Sábado, 6=Domingo


def format_datetime(dt: datetime) -> str:
    """Formata datetime para exibição na interface."""
    return dt.strftime("%d/%m/%Y %H:%M:%S")


def format_date(dt: datetime) -> str:
    """Formata apenas a data."""
    return dt.strftime("%d/%m/%Y")


# ─── Utilitários de arquivo ──────────────────────────────────

def ensure_dir(path: str) -> Path:
    """Garante que um diretório existe, criando-o se necessário."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_report_path(analysis_id: int, report_type: str = "full") -> Path:
    """Retorna o caminho para salvar um relatório PDF."""
    reports_dir = ensure_dir(get_env("REPORT_OUTPUT_DIR", "reports"))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cyberguard_report_{report_type}_{analysis_id}_{timestamp}.pdf"
    return reports_dir / filename


# ─── Utilitários de risco ────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "#EF4444",   # vermelho
    "high":     "#F97316",   # laranja
    "medium":   "#EAB308",   # amarelo
    "low":      "#22C55E",   # verde
}

SEVERITY_LABELS = {
    "critical": "🔴 Crítico",
    "high":     "🟠 Alto",
    "medium":   "🟡 Médio",
    "low":      "🟢 Baixo",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def score_to_severity(score: float) -> str:
    """
    Converte um score numérico (0-100) para nível de severidade.

    Args:
        score: Score de risco entre 0.0 e 100.0

    Returns:
        String do nível: 'critical', 'high', 'medium' ou 'low'
    """
    if score >= 75:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 25:
        return "medium"
    else:
        return "low"


def severity_to_color(severity: str) -> str:
    """Retorna o código hexadecimal de cor para uma severidade."""
    return SEVERITY_COLORS.get(severity.lower(), "#94A3B8")


def severity_label(severity: str) -> str:
    """Retorna o label formatado com emoji para exibição."""
    return SEVERITY_LABELS.get(severity.lower(), severity)
