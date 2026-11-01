import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean
from app.database import Base

class ThreatIntel(Base):
    __tablename__ = "threat_intel_cache"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    indicator = Column(String(128), unique=True, index=True, nullable=False)
    indicator_type = Column(String(32), default="IP") # IP, DOMAIN, HASH
    reputation_score = Column(Float, default=0.0)      # 0 to 100
    is_malicious = Column(Boolean, default=False)
    source = Column(String(64), default="MOCK_FEED")
    is_simulated = Column(Boolean, default=True)
    raw_response = Column(Text, default="{}")
    cached_at = Column(DateTime, default=datetime.datetime.utcnow)
