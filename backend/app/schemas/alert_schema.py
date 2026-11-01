from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict

class AlertBase(BaseModel):
    alert_id: str
    title: str
    detection_type: str = "RULE"  # RULE or ML_ANOMALY
    rule_id: str = ""
    severity: str = "MEDIUM"
    description: str
    confidence: float = 1.0
    triggering_event_ids: List[str] = []
    relevant_fields: Dict[str, Any] = {}
    status: str = "NEW"
    timestamp: datetime
    investigation_id: Optional[str] = None

class AlertCreate(AlertBase):
    pass

class AlertRead(BaseModel):
    id: int
    alert_id: str
    title: str
    detection_type: str
    rule_id: str
    severity: str
    description: str
    confidence: float
    triggering_event_ids: List[str]
    relevant_fields: Dict[str, Any]
    status: str
    timestamp: datetime
    investigation_id: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
