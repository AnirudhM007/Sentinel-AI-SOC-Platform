import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Float
from app.database import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    alert_id = Column(String(64), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False)
    detection_type = Column(String(32), default="RULE")  # RULE or ML_ANOMALY
    rule_id = Column(String(64), default="")
    severity = Column(String(32), default="MEDIUM")       # INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text, nullable=False)
    confidence = Column(Float, default=1.0)
    triggering_event_ids = Column(Text, default="[]")     # JSON array string of event_id strings
    relevant_fields = Column(Text, default="{}")          # JSON object string of IP, User, Count, etc.
    status = Column(String(32), default="NEW")            # NEW, INVESTIGATING, CLOSED
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    investigation_id = Column(String(64), nullable=True, index=True)
