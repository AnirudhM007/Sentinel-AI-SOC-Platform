import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Index
from app.database import Base

class LogEvent(Base):
    __tablename__ = "log_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime, index=True, nullable=False)
    hostname = Column(String(128), index=True, default="unknown")
    username = Column(String(128), index=True, default="unknown")
    source_ip = Column(String(64), index=True, default="")
    destination_ip = Column(String(64), index=True, default="")
    event_type = Column(String(64), index=True, nullable=False)
    event_id_native = Column(String(32), default="")
    process_name = Column(String(128), default="")
    command_line = Column(Text, default="")
    status = Column(String(32), default="UNKNOWN")  # SUCCESS, FAILURE, ATTEMPT, BLOCKED
    severity = Column(String(32), default="INFORMATIONAL") # INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
    raw_event = Column(Text, nullable=False)
    file_source = Column(String(128), default="manual_upload")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    __table_args__ = (
        Index("idx_log_event_time_user", "timestamp", "username"),
        Index("idx_log_event_time_ip", "timestamp", "source_ip"),
    )
