import logging
from typing import Dict, Any
from langgraph.graph import StateGraph, START, END
from app.agents.state import AgentState
from app.agents.triage_agent import soc_triage_node
from app.agents.log_agent import log_investigation_node
from app.agents.threat_agent import threat_intel_node
from app.agents.mitre_agent import mitre_mapping_node
from app.agents.analysis_agent import incident_analysis_node
from app.agents.validation_agent import validation_agent_node
from app.agents.report_agent import report_generation_node

logger = logging.getLogger("sentinel.langgraph")

def route_triage_decision(state: AgentState) -> str:
    """
    Conditional routing edge after SOC Triage:
    If suspicious activity is detected, route to deep Log Investigation.
    Otherwise, if benign, jump directly to final Report Generation.
    """
    triage = state.get("triage_verdict", {})
    if triage.get("is_suspicious", False):
        return "log_investigation"
    return "report_generation"

def route_validation_decision(state: AgentState) -> str:
    """
    Conditional routing edge after Validation:
    If discrepancies are found and iterations remain, loop back to Log Investigation.
    Otherwise, proceed to Report Generation.
    """
    val = state.get("validation_result", {})
    if val.get("needs_reinvestigation", False):
        return "log_investigation"
    return "report_generation"

def create_investigation_graph():
    """
    Constructs and compiles the full LangGraph stateful multi-agent workflow.
    """
    builder = StateGraph(AgentState)

    # 1. Register specialized agent nodes
    builder.add_node("soc_triage", soc_triage_node)
    builder.add_node("log_investigation", log_investigation_node)
    builder.add_node("threat_intelligence", threat_intel_node)
    builder.add_node("mitre_mapping", mitre_mapping_node)
    builder.add_node("incident_analysis", incident_analysis_node)
    builder.add_node("validation", validation_agent_node)
    builder.add_node("report_generation", report_generation_node)

    # 2. Add control-flow edges
    builder.add_edge(START, "soc_triage")

    builder.add_conditional_edges(
        "soc_triage",
        route_triage_decision,
        {
            "log_investigation": "log_investigation",
            "report_generation": "report_generation"
        }
    )

    builder.add_edge("log_investigation", "threat_intelligence")
    builder.add_edge("threat_intelligence", "mitre_mapping")
    builder.add_edge("mitre_mapping", "incident_analysis")
    builder.add_edge("incident_analysis", "validation")

    builder.add_conditional_edges(
        "validation",
        route_validation_decision,
        {
            "log_investigation": "log_investigation",
            "report_generation": "report_generation"
        }
    )

    builder.add_edge("report_generation", END)

    compiled_graph = builder.compile()
    return compiled_graph

investigation_graph = create_investigation_graph()
