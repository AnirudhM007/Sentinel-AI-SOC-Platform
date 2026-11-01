from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict
from app.schemas.report_schema import IncidentReport

class InvestigationStartRequest(BaseModel):
    alert_id: Optional[str] = None
    event_ids: Optional[List[str]] = None
    title: Optional[str] = None
    description: Optional[str] = None
    manual_context: Optional[str] = None

class InvestigationStepTrace(BaseModel):
    step_id: int
    agent_name: str
    action: str
    status: str # "RUNNING", "COMPLETED", "ERROR", "NEEDS_CLARIFICATION"
    timestamp: str
    thought: Optional[str] = None
    tool_name: Optional[str] = None
    tool_input: Optional[Dict[str, Any]] = None
    tool_output: Optional[Dict[str, Any]] = None
    findings_summary: Optional[str] = None

class InvestigationRead(BaseModel):
    id: int
    investigation_id: str
    title: str
    status: str
    trigger_alert_id: Optional[str] = None
    severity: str
    summary: str
    agent_traces: List[InvestigationStepTrace] = []
    report_data: Optional[IncidentReport] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
