"""
database.py — Modelos e operações do banco de dados SQLite.
"""

import json
from datetime import datetime
from pathlib import Path

from sqlalchemy import (
    create_engine, Column, Integer, Float, String,
    DateTime, Text, Boolean, ForeignKey, func
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship
from loguru import logger

from src.utils import get_env

DATABASE_URL = get_env("DATABASE_URL", "sqlite:///cyberguard.db")
engine = create_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})


class Base(DeclarativeBase):
    pass


# ─── Modelos ──────────────────────────────────────────────────

class Analysis(Base):
    __tablename__ = "analyses"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    filename        = Column(String(255), nullable=False)
    file_type       = Column(String(10), nullable=False)
    analyzed_at     = Column(DateTime, default=datetime.now)
    total_events    = Column(Integer, default=0)
    total_incidents = Column(Integer, default=0)
    critical_count  = Column(Integer, default=0)
    high_count      = Column(Integer, default=0)
    medium_count    = Column(Integer, default=0)
    low_count       = Column(Integer, default=0)
    avg_risk_score  = Column(Float, default=0.0)
    status          = Column(String(20), default="completed")

    incidents = relationship("Incident", back_populates="analysis",
                             cascade="all, delete-orphan")


class Incident(Base):
    __tablename__ = "incidents"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id   = Column(Integer, ForeignKey("analyses.id"), nullable=False)
    incident_type = Column(String(50), nullable=False)
    severity      = Column(String(20), nullable=False)
    risk_score    = Column(Float, nullable=False)
    source_ip     = Column(String(50))
    target_user   = Column(String(100))
    first_seen    = Column(DateTime)
    last_seen     = Column(DateTime)
    event_count   = Column(Integer, default=1)
    description   = Column(Text)
    raw_events    = Column(Text)  # JSON string

    analysis = relationship("Analysis", back_populates="incidents")


# ─── Inicialização ────────────────────────────────────────────

def init_db() -> None:
    """Cria todas as tabelas se não existirem."""
    Base.metadata.create_all(engine)
    logger.info("Banco de dados inicializado.")


# ─── Operações ────────────────────────────────────────────────

def save_analysis(filename: str, total_events: int, scored: list) -> int:
    """
    Salva uma análise completa no banco.
    Retorna o ID gerado.
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "unknown"

    critical = sum(1 for s in scored if s["severity"] == "critical")
    high     = sum(1 for s in scored if s["severity"] == "high")
    medium   = sum(1 for s in scored if s["severity"] == "medium")
    low      = sum(1 for s in scored if s["severity"] == "low")
    avg      = round(sum(s["risk_score"] for s in scored) / len(scored), 2) if scored else 0.0

    with Session(engine) as session:
        analysis = Analysis(
            filename        = filename,
            file_type       = ext,
            total_events    = total_events,
            total_incidents = len(scored),
            critical_count  = critical,
            high_count      = high,
            medium_count    = medium,
            low_count       = low,
            avg_risk_score  = avg,
        )
        session.add(analysis)
        session.flush()  # gera o ID

        for s in scored:
            raw = json.dumps(
                [{k: str(v) for k, v in e.items()} for e in s.get("raw_events", [])[:10]],
                ensure_ascii=False
            )
            incident = Incident(
                analysis_id   = analysis.id,
                incident_type = s["incident_type"],
                severity      = s["severity"],
                risk_score    = s["risk_score"],
                source_ip     = s["source_ip"],
                target_user   = str(s["target_user"]),
                first_seen    = s["first_seen"],
                last_seen     = s["last_seen"],
                event_count   = s["event_count"],
                description   = s["description"],
                raw_events    = raw,
            )
            session.add(incident)

        session.commit()
        analysis_id = analysis.id
        logger.info(f"Análise #{analysis_id} salva — {len(scored)} incidentes")
        return analysis_id


def get_analysis_history(limit: int = 20) -> list[dict]:
    """Retorna histórico de análises (mais recentes primeiro)."""
    with Session(engine) as session:
        rows = (session.query(Analysis)
                .order_by(Analysis.analyzed_at.desc())
                .limit(limit)
                .all())
        return [
            {
                "id":             r.id,
                "filename":       r.filename,
                "file_type":      r.file_type,
                "analyzed_at":    r.analyzed_at,
                "total_events":   r.total_events,
                "total_incidents":r.total_incidents,
                "critical_count": r.critical_count,
                "high_count":     r.high_count,
                "medium_count":   r.medium_count,
                "low_count":      r.low_count,
                "avg_risk_score": r.avg_risk_score,
                "status":         r.status,
            }
            for r in rows
        ]


def get_analysis_incidents(analysis_id: int) -> list[dict]:
    """Retorna incidentes de uma análise específica."""
    with Session(engine) as session:
        rows = (session.query(Incident)
                .filter(Incident.analysis_id == analysis_id)
                .order_by(Incident.risk_score.desc())
                .all())
        return [
            {
                "id":            r.id,
                "incident_type": r.incident_type,
                "severity":      r.severity,
                "risk_score":    r.risk_score,
                "source_ip":     r.source_ip,
                "target_user":   r.target_user,
                "first_seen":    r.first_seen,
                "last_seen":     r.last_seen,
                "event_count":   r.event_count,
                "description":   r.description,
            }
            for r in rows
        ]


def get_stats_summary() -> dict:
    """Retorna estatísticas globais do banco."""
    with Session(engine) as session:
        total_analyses  = session.query(func.count(Analysis.id)).scalar() or 0
        total_incidents = session.query(func.count(Incident.id)).scalar() or 0
        total_critical  = session.query(func.count(Incident.id))\
                            .filter(Incident.severity == "critical").scalar() or 0
        return {
            "total_analyses":  total_analyses,
            "total_incidents": total_incidents,
            "total_critical":  total_critical,
        }