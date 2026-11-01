export interface LogEvent {
  id: number;
  event_id: string;
  timestamp: string;
  hostname: string;
  username: string;
  source_ip: string;
  destination_ip: string;
  event_type: string;
  event_id_native: string;
  process_name: string;
  command_line: string;
  status: string;
  severity: 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  raw_event: string;
  file_source: string;
  created_at: string;
}

export interface Alert {
  id: number;
  alert_id: string;
  title: string;
  detection_type: 'RULE' | 'ML_ANOMALY';
  rule_id: string;
  severity: 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  confidence: number;
  triggering_event_ids: string[];
  relevant_fields: Record<string, any>;
  status: 'NEW' | 'INVESTIGATING' | 'CLOSED';
  timestamp: string;
  investigation_id?: string;
  triggering_events?: LogEvent[];
}

export interface InvestigationTraceStep {
  step_id: number;
  agent_name: string;
  action: string;
  status: 'RUNNING' | 'COMPLETED' | 'ERROR' | 'NEEDS_CLARIFICATION';
  timestamp: string;
  thought?: string;
  tool_name?: string;
  tool_input?: Record<string, any>;
  tool_output?: Record<string, any>;
  findings_summary?: string;
}

export interface TimelineEntry {
  timestamp: string;
  event_id: string;
  event_type: string;
  summary: string;
  severity: string;
  evidence: string;
}

export interface MitreMappingEntry {
  technique_id: string;
  technique_name: string;
  tactic: string;
  reason: string;
  confidence: number;
  supporting_evidence: string[];
}

export interface ThreatFindingEntry {
  indicator: string;
  indicator_type: string;
  reputation_score: number;
  is_malicious: boolean;
  source: string;
  is_simulated: boolean;
  summary: string;
  details?: Record<string, any>;
}

export interface RemediationAction {
  action_id: string;
  priority: string;
  title: string;
  description: string;
  requires_human_approval: boolean;
}

export interface IncidentReport {
  investigation_id: string;
  report_title: string;
  generated_at: string;
  incident_overview: string;
  executive_summary: string;
  severity: 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  severity_rationale: string;
  affected_assets: {
    hosts: string[];
    users: string[];
    ips: string[];
  };
  suspicious_indicators: string[];
  event_timeline: TimelineEntry[];
  investigation_methodology: string;
  threat_intelligence_findings: ThreatFindingEntry[];
  mitre_attack_mappings: MitreMappingEntry[];
  root_cause_assessment: string;
  potential_impact: string;
  recommended_remediation: RemediationAction[];
  evidence_references: string[];
  investigation_limitations: string;
  validation_status: string;
  validation_notes: string[];
}

export interface Investigation {
  id: number;
  investigation_id: string;
  title: string;
  status: 'IN_PROGRESS' | 'COMPLETED' | 'FAILED';
  severity: string;
  summary: string;
  created_at: string;
  updated_at: string;
  agent_traces?: InvestigationTraceStep[];
  report?: IncidentReport;
}

export interface DashboardSummary {
  total_events: number;
  total_investigations: number;
  active_investigations: number;
  critical_incidents: number;
  high_incidents: number;
  anomaly_count: number;
  total_alerts: number;
  severity_distribution: Record<string, number>;
  top_affected_hosts: { hostname: string; event_count: number }[];
  recent_alerts: any[];
  recent_investigations: any[];
  event_activity_chart: { time: string; total: number; auth_failures: number; normal: number }[];
}

export interface ScenarioMeta {
  id: string;
  title: string;
  filename: string;
  description: string;
  simulated: boolean;
  category: string;
}

export interface AppSettings {
  project_name: string;
  version: string;
  mock_mode: boolean;
  llm_provider: string;
  openai_model: string;
  has_openai_key: boolean;
  has_abuseipdb_key: boolean;
  has_virustotal_key: boolean;
  brute_force_threshold: number;
  time_window_minutes: number;
  max_investigation_loops: number;
  max_upload_size_mb: number;
}
