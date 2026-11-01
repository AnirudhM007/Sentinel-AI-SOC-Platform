from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class TimelineEntry(BaseModel):
    timestamp: str
    event_id: str
    event_type: str
    summary: str
    severity: str
    evidence: str

class MitreMappingEntry(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    reason: str
    confidence: float
    supporting_evidence: List[str]

class ThreatFindingEntry(BaseModel):
    indicator: str
    indicator_type: str
    reputation_score: float
    is_malicious: bool
    source: str
    is_simulated: bool
    summary: str

class RemediationAction(BaseModel):
    action_id: str
    priority: str
    title: str
    description: str
    requires_human_approval: bool = True

class IncidentReport(BaseModel):
    investigation_id: str
    report_title: str
    generated_at: str
    incident_overview: str
    executive_summary: str
    severity: str  # INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
    severity_rationale: str
    affected_assets: Dict[str, List[str]] # {"hosts": [...], "users": [...], "ips": [...]}
    suspicious_indicators: List[str]
    event_timeline: List[TimelineEntry]
    investigation_methodology: str
    threat_intelligence_findings: List[ThreatFindingEntry]
    mitre_attack_mappings: List[MitreMappingEntry]
    root_cause_assessment: str
    potential_impact: str
    recommended_remediation: List[RemediationAction]
    evidence_references: List[str]
    investigation_limitations: str
    validation_status: str # "PASSED", "VERIFIED_WITH_CAVEATS", "FLAGGED"
    validation_notes: List[str]
