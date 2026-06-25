"""
log_parser.py — Parser e validador de arquivos de log.

Suporta: CSV, JSON, TXT (syslog)
Normaliza colunas para o padrão interno do CyberGuard AI.
"""

import io
import json
import re
import pandas as pd
from datetime import datetime
from loguru import logger

REQUIRED_COLUMNS = {"timestamp", "source_ip", "username", "action", "status"}

COLUMN_ALIASES = {
    "timestamp": ["timestamp", "time", "datetime", "date_time", "event_time", "ts", "date", "created_at"],
    "source_ip": ["source_ip", "ip", "src_ip", "ip_address", "client_ip", "remote_ip", "host", "src"],
    "username":  ["username", "user", "user_name", "login", "account", "userid", "user_id", "principal"],
    "action":    ["action", "event", "event_type", "activity", "type", "method", "request", "operation"],
    "status":    ["status", "result", "outcome", "response", "state", "event_result", "auth_result"],
}

SYSLOG_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+(?P<action>\S+?)(?:\[\d+\])?:\s+"
    r"(?P<status>\w+)\s+"
    r"user=(?P<username>\S+)\s+"
    r"src=(?P<source_ip>\S+)"
    r"(?:\s+msg=\"(?P<details>[^\"]+)\")?",
    re.IGNORECASE,
)


class LogParseError(Exception):
    pass


def parse_log_file(file_content: bytes, filename: str) -> pd.DataFrame:
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    logger.info(f"Iniciando parse: {filename} ({len(file_content)} bytes, ext={ext})")

    try:
        if ext == "csv":
            df = _parse_csv(file_content)
        elif ext == "json":
            df = _parse_json(file_content)
        elif ext == "txt":
            df = _parse_txt(file_content)
        else:
            df = _infer_and_parse(file_content, filename)
    except LogParseError:
        raise
    except Exception as e:
        raise LogParseError(f"Erro inesperado ao processar '{filename}': {e}") from e

    df = normalize_columns(df)

    is_valid, errors = validate_dataframe(df)
    if not is_valid:
        raise LogParseError(
            "Arquivo inválido — colunas obrigatórias ausentes:\n" +
            "\n".join(f"  • {e}" for e in errors)
        )

    df = _convert_types(df)

    if "details" not in df.columns:
        df["details"] = ""

    df = df.sort_values("timestamp").reset_index(drop=True)
    logger.info(f"Parse concluído: {len(df)} eventos")
    return df


def _parse_csv(content: bytes) -> pd.DataFrame:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = content.decode("latin-1")
    try:
        df = pd.read_csv(io.StringIO(text))
    except Exception as e:
        raise LogParseError(f"CSV inválido: {e}")
    if df.empty:
        raise LogParseError("O arquivo CSV está vazio.")
    return df


def _parse_json(content: bytes) -> pd.DataFrame:
    try:
        text = content.decode("utf-8")
        data = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise LogParseError(f"JSON inválido: {e}")

    if isinstance(data, list):
        events = data
    elif isinstance(data, dict):
        for key in ["events", "logs", "data", "records", "items"]:
            if key in data and isinstance(data[key], list):
                events = data[key]
                break
        else:
            raise LogParseError(
                "JSON deve ser um array ou objeto com chave 'events', 'logs', 'data', 'records' ou 'items'."
            )
    else:
        raise LogParseError("Formato JSON não reconhecido.")

    if not events:
        raise LogParseError("O arquivo JSON não contém eventos.")

    try:
        df = pd.DataFrame(events)
    except Exception as e:
        raise LogParseError(f"Não foi possível converter JSON para tabela: {e}")
    return df


def _parse_txt(content: bytes) -> pd.DataFrame:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not lines:
        raise LogParseError("O arquivo TXT está vazio.")

    rows = []
    failed = 0
    current_year = datetime.now().year

    for line in lines:
        m = SYSLOG_PATTERN.search(line)
        if m:
            g = m.groupdict()
            ts_str = f"{g['month']} {g['day'].zfill(2)} {g['time']} {current_year}"
            try:
                ts = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
            except ValueError:
                ts = datetime.now()
            rows.append({
                "timestamp": ts,
                "source_ip": g.get("source_ip", ""),
                "username":  g.get("username", ""),
                "action":    g.get("action", ""),
                "status":    g.get("status", "").lower(),
                "details":   g.get("details", ""),
            })
        else:
            failed += 1

    if not rows:
        raise LogParseError(
            "Nenhuma linha do TXT pôde ser interpretada.\n"
            "Formato esperado: 'Jun 25 14:30:01 host ACTION[pid]: STATUS user=X src=Y msg=\"...\"'"
        )
    if failed > 0:
        logger.warning(f"{failed} linhas ignoradas no TXT.")
    return pd.DataFrame(rows)


def _infer_and_parse(content: bytes, filename: str) -> pd.DataFrame:
    try:
        text = content[:500].decode("utf-8")
    except UnicodeDecodeError:
        text = content[:500].decode("latin-1")
    text = text.strip()
    if text.startswith("[") or text.startswith("{"):
        return _parse_json(content)
    elif "," in text and "\n" in text:
        return _parse_csv(content)
    else:
        return _parse_txt(content)


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    rename_map = {}
    for standard_name, aliases in COLUMN_ALIASES.items():
        if standard_name in df.columns:
            continue
        for alias in aliases:
            if alias in df.columns:
                rename_map[alias] = standard_name
                break
    if rename_map:
        df = df.rename(columns=rename_map)
    return df


def validate_dataframe(df: pd.DataFrame) -> tuple[bool, list[str]]:
    errors = []
    present = set(df.columns)
    for col in REQUIRED_COLUMNS:
        if col not in present:
            errors.append(
                f"Coluna '{col}' não encontrada. Nomes aceitos: {COLUMN_ALIASES.get(col, [col])}"
            )
    if df.empty:
        errors.append("O arquivo não contém dados.")
    return len(errors) == 0, errors


def _convert_types(df: pd.DataFrame) -> pd.DataFrame:
    if "timestamp" in df.columns and not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
        formats = [
            "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ",
            "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%d",
        ]
        converted = False
        for fmt in formats:
            try:
                df["timestamp"] = pd.to_datetime(df["timestamp"], format=fmt)
                converted = True
                break
            except (ValueError, TypeError):
                continue
        if not converted:
            try:
                df["timestamp"] = pd.to_datetime(df["timestamp"], infer_datetime_format=True)
            except Exception:
                raise LogParseError(
                    "Não foi possível interpretar 'timestamp'. Formato esperado: YYYY-MM-DD HH:MM:SS"
                )

    if "status" in df.columns:
        df["status"] = df["status"].astype(str).str.lower().str.strip()
        df["status"] = df["status"].replace({
            "ok": "success", "accepted": "success", "pass": "success",
            "passed": "success", "allow": "success", "allowed": "success",
            "fail": "failure", "failed": "failure", "deny": "failure",
            "denied": "failure", "reject": "failure", "rejected": "failure",
            "error": "failure", "blocked": "failure",
        })

    for col in ["source_ip", "username", "action"]:
        if col in df.columns:
            df[col] = df[col].astype(str).str.strip()

    df = df.dropna(subset=["timestamp"])
    return df


def get_preview_stats(df: pd.DataFrame) -> dict:
    return {
        "total_events":   len(df),
        "date_start":     df["timestamp"].min(),
        "date_end":       df["timestamp"].max(),
        "unique_ips":     df["source_ip"].nunique(),
        "unique_users":   df["username"].nunique(),
        "success_count":  int((df["status"] == "success").sum()),
        "failure_count":  int((df["status"] == "failure").sum()),
        "unique_actions": df["action"].nunique(),
        "columns":        list(df.columns),
    }