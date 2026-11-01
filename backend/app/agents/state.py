from typing import TypedDict, List, Dict, Any, Optional

class AgentState(TypedDict):
    investigation_id: str
    title: str
    events: List[Dict[str, Any]]
    alerts: List[Dict[str, Any]]
    triage_verdict: Dict[str, Any]
    log_findings: Dict[str, Any]
    threat_intel_findings: List[Dict[str, Any]]
    mitre_mappings: List[Dict[str, Any]]
    incident_analysis: Dict[str, Any]
    validation_result: Dict[str, Any]
    final_report: Dict[str, Any]
    traces: List[Dict[str, Any]]
    iteration_count: int
    error_logs: List[str]
