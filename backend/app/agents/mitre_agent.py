from datetime import datetime
from typing import Dict, Any, List
from app.agents.state import AgentState
from app.mitre.mapper import mitre_mapper

def mitre_mapping_node(state: AgentState) -> Dict[str, Any]:
    """
    Agent 4: MITRE ATT&CK Mapping Agent
    Correlates alerts and log telemetry against the curated MITRE ATT&CK matrix.
    """
    events = state.get("events", [])
    alerts = state.get("alerts", [])
    traces = list(state.get("traces", []))
    step_id = len(traces) + 1
    ts_now = datetime.utcnow().isoformat() + "Z"

    # Map behaviors
    mappings = mitre_mapper.map_behaviors(alerts, events)

    mapped_techniques = [f"{m['technique_id']} ({m['technique_name']})" for m in mappings]

    trace_step = {
        "step_id": step_id,
        "agent_name": "MITRE ATT&CK Mapping Agent",
        "action": "Behavioral Matrix Alignment",
        "status": "COMPLETED",
        "timestamp": ts_now,
        "thought": (
            f"Cross-referencing {len(alerts)} alerts and observable telemetry against MITRE ATT&CK Enterprise Matrix. "
            f"Validating technique IDs, tactics, and supporting evidence."
        ),
        "tool_name": "map_mitre_techniques",
        "tool_input": {"alerts_count": len(alerts), "events_count": len(events)},
        "tool_output": {"mappings_count": len(mappings), "technique_ids": [m["technique_id"] for m in mappings]},
        "findings_summary": (
            f"Mapped {len(mappings)} technique(s): {', '.join(mapped_techniques) or 'No specific techniques triggered (Benign activity)'}."
        )
    }

    traces.append(trace_step)

    return {
        "mitre_mappings": mappings,
        "traces": traces
    }
