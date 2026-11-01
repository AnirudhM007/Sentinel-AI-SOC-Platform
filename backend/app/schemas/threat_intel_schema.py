from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, ConfigDict

class ThreatIntelResult(BaseModel):
    indicator: str
    indicator_type: str = "IP"
    reputation_score: float = 0.0  # 0 to 100
    is_malicious: bool = False
    source: str = "MOCK_FEED"
    is_simulated: bool = True
    details: Dict[str, Any] = {}
    cached_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
