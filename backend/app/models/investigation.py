import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime
from app.database import Base

class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    investigation_id = Column(String(64), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False)
    status = Column(String(32), default="IN_PROGRESS")  # IN_PROGRESS, COMPLETED, FAILED
    trigger_alert_id = Column(String(64), nullable=True)
    severity = Column(String(32), default="MEDIUM")
    summary = Column(Text, default="")
    agent_traces = Column(Text, default="[]")           # JSON array of agent execution step logs
    report_data = Column(Text, default="{}")            # Complete structured investigation report JSON
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
