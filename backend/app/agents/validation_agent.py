from datetime import datetime
from typing import Dict, Any, List
from app.agents.state import AgentState
from app.agents.tools import verify_event_references
from app.config import settings

def validation_agent_node(state: AgentState) -> Dict[str, Any]:
    """
    Agent 6: Validation Agent
    Fact-checks evidence integrity, confirms referenced events exist in telemetry, validates MITRE support.
    Decides if investigation should loop back for deeper inspection or proceed to reporting.
    """
    events = state.get("events", [])
    alerts = state.get("alerts", [])
    log_findings = state.get("log_findings", {})
    mitre_mappings = state.get("mitre_mappings", [])
    analysis = state.get("incident_analysis", {})
    iteration_count = state.get("iteration_count", 0) + 1
    traces = list(state.get("traces", []))
    step_id = len(traces) + 1
    ts_now = datetime.utcnow().isoformat() + "Z"

    validation_issues: List[str] = []

    # 1. Verify all event IDs referenced in alerts and timeline actually exist in raw events
    timeline = log_findings.get("event_timeline", [])
    timeline_ids = [t["event_id"] for t in timeline if t.get("event_id")]
    alert_event_ids = [eid for a in alerts for eid in a.get("triggering_event_ids", [])]
    referenced_ids = list(set(timeline_ids + alert_event_ids))

    ref_verification = verify_event_references(referenced_ids, events)
    if not ref_verification["is_fully_grounded"]:
        validation_issues.append(
            f"Grounding failure: {ref_verification['missing_count']} referenced event IDs could not be located in source log telemetry."
        )

    # 2. Check MITRE mappings have supporting evidence
    for m in mitre_mappings:
        if not m.get("supporting_evidence"):
            validation_issues.append(f"MITRE technique {m.get('technique_id')} lacks concrete log evidence references.")

    # 3. Check severity consistency
    assigned_sev = analysis.get("severity")
    if assigned_sev == "CRITICAL" and not any(a.get("severity") in ["CRITICAL", "HIGH"] for a in alerts):
        validation_issues.append("Severity inconsistency: CRITICAL assigned without corresponding high/critical alerts.")

    # Determine if loop-back is warranted
    is_valid = len(validation_issues) == 0
    needs_reinvestigation = False
    
    # If there are unresolved discrepancies and we haven't reached the max loops, trigger reinvestigation
    if not is_valid and iteration_count < settings.MAX_INVESTIGATION_LOOPS:
        needs_reinvestigation = True

    validation_result = {
        "is_valid": is_valid,
        "needs_reinvestigation": needs_reinvestigation,
        "iteration_count": iteration_count,
        "validation_issues": validation_issues,
        "verified_events_count": ref_verification["verified_count"],
        "total_referenced_events": ref_verification["total_referenced"],
        "status": "PASSED" if is_valid else ("REINVESTIGATION_REQUESTED" if needs_reinvestigation else "VERIFIED_WITH_CAVEATS")
    }

    status_str = "COMPLETED" if not needs_reinvestigation else "NEEDS_CLARIFICATION"
    summary_text = (
        f"Validation PASSED. All {ref_verification['verified_count']} referenced events verified against source logs. MITRE mappings confirmed."
        if is_valid else (
            f"Validation flagged {len(validation_issues)} issue(s): {'; '.join(validation_issues)}. "
            f"{'Triggering loopback iteration.' if needs_reinvestigation else 'Max iteration reached; proceeding with caveats recorded.'}"
        )
    )

    trace_step = {
        "step_id": step_id,
        "agent_name": "Validation Agent",
        "action": "Evidence Verification and Fact Checking",
        "status": status_str,
        "timestamp": ts_now,
        "thought": (
            f"Auditing evidence integrity for iteration {iteration_count}. "
            f"Cross-checking {len(referenced_ids)} referenced event IDs against ingested logs. "
            f"Validating MITRE ATT&CK technique citations."
        ),
        "tool_name": "verify_event_references",
        "tool_input": {"total_referenced_ids": len(referenced_ids)},
        "tool_output": ref_verification,
        "findings_summary": summary_text
    }

    traces.append(trace_step)

    return {
        "validation_result": validation_result,
        "iteration_count": iteration_count,
        "traces": traces
    }
