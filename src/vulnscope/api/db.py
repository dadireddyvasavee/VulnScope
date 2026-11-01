import json
import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, String, Integer, Float, Text, DateTime, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, relationship


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    files: Mapped[int] = mapped_column(Integer)
    loc: Mapped[int] = mapped_column(Integer)
    seconds: Mapped[float] = mapped_column(Float)
    severity_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    findings = relationship("FindingRow", back_populates="scan", cascade="all, delete-orphan")


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    cwe: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(24), default="open")   # open | confirmed | false_positive | fixed
    data_json: Mapped[str] = mapped_column(Text)
    scan = relationship("Scan", back_populates="findings")


def make_session(url=None):
    url = url or os.getenv("VULNSCOPE_DB_URL", "sqlite:///vulnscope.db")
    eng = create_engine(url, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {})
    Base.metadata.create_all(eng)
    return sessionmaker(eng, expire_on_commit=False)


def save_scan(Session, name, result) -> int:
    with Session() as s:
        sc = Scan(name=name, files=result["files"], loc=result["loc"], seconds=result["seconds"],
                  severity_json=json.dumps(result["severity_breakdown"]))
        sc.findings = [FindingRow(cwe=f["cwe"], severity=f["severity"], data_json=json.dumps(f)) for f in result["findings"]]
        s.add(sc)
        s.commit()
        return sc.id
