"""Persistence via SQLAlchemy. Defaults to SQLite; set AEGIS_DB_URL=postgresql+psycopg2://... for PostgreSQL."""
import json
import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, String, Float, Text, DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class Analysis(Base):
    __tablename__ = "analyses"
    id: Mapped[int] = mapped_column(primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    verdict: Mapped[str] = mapped_column(String(16))
    score: Mapped[float] = mapped_column(Float)
    report_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


def make_session(url: str | None = None):
    url = url or os.getenv("AEGIS_DB_URL", "sqlite:///aegis.db")
    engine = create_engine(url, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {})
    Base.metadata.create_all(engine)
    return sessionmaker(engine, expire_on_commit=False)


def save(Session, report: dict) -> int:
    with Session() as s:
        row = Analysis(sha256=report["sample"]["sha256"], verdict=report["verdict"],
                       score=report["risk_score"], report_json=json.dumps(report))
        s.add(row)
        s.commit()
        return row.id
