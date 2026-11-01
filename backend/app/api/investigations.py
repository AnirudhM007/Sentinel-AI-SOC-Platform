import os
import json
import uuid
import asyncio
from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session
from app.database import get_db, SessionLocal
from app.models.investigation import Investigation
from app.models.alert import Alert
from app.models.log_event import LogEvent
from app.schemas.investigation_schema import InvestigationStartRequest
from app.agents.workflow import investigation_graph
from app.agents.state import AgentState
from app.reports.pdf_generator import generate_incident_pdf

router = APIRouter(prefix="/investigations", tags=["Investigations"])

PDF_STORAGE_DIR = os.path.join(os.getcwd(), "storage", "reports")

def _run_graph_investigation(inv_id: str, title: str, events: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    initial_state: AgentState = {
        "investigation_id": inv_id,
        "title": title,
        "events": events,
        "alerts": alerts,
        "triage_verdict": {},
        "log_findings": {},
        "threat_intel_findings": [],
        "mitre_mappings": [],
        "incident_analysis": {},
        "validation_result": {},
        "final_report": {},
        "traces": [],
        "iteration_count": 0,
        "error_logs": []
    }

    final_state = investigation_graph.invoke(initial_state)
    return final_state

@router.post("/start")
def start_investigation(req: InvestigationStartRequest, db: Session = Depends(get_db)):
    inv_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
    
    # 1. Fetch relevant alerts & events
    alerts_to_investigate = []
    events_to_investigate = []
    title = req.title or "Security Event Investigation"

    if req.alert_id:
        target_alert = db.query(Alert).filter(Alert.alert_id == req.alert_id).first()
        if target_alert:
            title = f"Investigation: {target_alert.title}"
            alerts_to_investigate.append({
                "alert_id": target_alert.alert_id,
                "title": target_alert.title,
                "detection_type": target_alert.detection_type,
                "rule_id": target_alert.rule_id,
                "severity": target_alert.severity,
                "description": target_alert.description,
                "confidence": target_alert.confidence,
                "triggering_event_ids": json.loads(target_alert.triggering_event_ids or "[]"),
                "relevant_fields": json.loads(target_alert.relevant_fields or "{}"),
                "timestamp": str(target_alert.timestamp)
            })

            # Fetch triggering events + surrounding events for context
            t_ids = json.loads(target_alert.triggering_event_ids or "[]")
            if t_ids:
                db_evs = db.query(LogEvent).filter(LogEvent.event_id.in_(t_ids)).all()
                for e in db_evs:
                    events_to_investigate.append({
                        "event_id": e.event_id,
                        "timestamp": e.timestamp,
                        "hostname": e.hostname,
                        "username": e.username,
                        "source_ip": e.source_ip,
                        "destination_ip": e.destination_ip,
                        "event_type": e.event_type,
                        "event_id_native": e.event_id_native,
                        "process_name": e.process_name,
                        "command_line": e.command_line,
                        "status": e.status,
                        "severity": e.severity,
                        "raw_event": e.raw_event
                    })

    if req.event_ids:
        db_evs = db.query(LogEvent).filter(LogEvent.event_id.in_(req.event_ids)).all()
        for e in db_evs:
            events_to_investigate.append({
                "event_id": e.event_id,
                "timestamp": e.timestamp,
                "hostname": e.hostname,
                "username": e.username,
                "source_ip": e.source_ip,
                "destination_ip": e.destination_ip,
                "event_type": e.event_type,
                "event_id_native": e.event_id_native,
                "process_name": e.process_name,
                "command_line": e.command_line,
                "status": e.status,
                "severity": e.severity,
                "raw_event": e.raw_event
            })

    # If no specific events were passed, pull recent security events from DB
    if not events_to_investigate:
        recent_evs = db.query(LogEvent).order_by(LogEvent.timestamp.desc()).limit(50).all()
        for e in recent_evs:
            events_to_investigate.append({
                "event_id": e.event_id,
                "timestamp": e.timestamp,
                "hostname": e.hostname,
                "username": e.username,
                "source_ip": e.source_ip,
                "destination_ip": e.destination_ip,
                "event_type": e.event_type,
                "event_id_native": e.event_id_native,
                "process_name": e.process_name,
                "command_line": e.command_line,
                "status": e.status,
                "severity": e.severity,
                "raw_event": e.raw_event
            })

    if not alerts_to_investigate:
        recent_alts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(10).all()
        for a in recent_alts:
            alerts_to_investigate.append({
                "alert_id": a.alert_id,
                "title": a.title,
                "detection_type": a.detection_type,
                "rule_id": a.rule_id,
                "severity": a.severity,
                "description": a.description,
                "confidence": a.confidence,
                "triggering_event_ids": json.loads(a.triggering_event_ids or "[]"),
                "relevant_fields": json.loads(a.relevant_fields or "{}"),
                "timestamp": str(a.timestamp)
            })

    # Create investigation record
    inv_record = Investigation(
        investigation_id=inv_id,
        title=title,
        status="IN_PROGRESS",
        trigger_alert_id=req.alert_id,
        severity="MEDIUM",
        summary="Investigation initiated; executing LangGraph multi-agent orchestration.",
        agent_traces="[]",
        report_data="{}"
    )
    db.add(inv_record)
    db.commit()

    # 2. Run LangGraph workflow synchronously for instant reliable output
    final_state = _run_graph_investigation(inv_id, title, events_to_investigate, alerts_to_investigate)

    # 3. Save finalized state to database
    report = final_state.get("final_report", {})
    traces = final_state.get("traces", [])
    assigned_sev = report.get("severity") or final_state.get("incident_analysis", {}).get("severity", "MEDIUM")
    exec_summary = report.get("executive_summary", "Completed LangGraph multi-agent investigation.")

    inv_record.status = "COMPLETED"
    inv_record.severity = assigned_sev
    inv_record.summary = exec_summary
    inv_record.agent_traces = json.dumps(traces)
    inv_record.report_data = json.dumps(report)
    
    if req.alert_id:
        alt = db.query(Alert).filter(Alert.alert_id == req.alert_id).first()
        if alt:
            alt.status = "INVESTIGATING"
            alt.investigation_id = inv_id

    db.commit()

    return {
        "investigation_id": inv_id,
        "title": title,
        "status": "COMPLETED",
        "severity": assigned_sev,
        "summary": exec_summary,
        "total_traces": len(traces),
        "report_generated": bool(report),
        "report": report,
        "traces": traces
    }

@router.get("")
def list_investigations(limit: int = 50, offset: int = 0, db: Session = Depends(get_db)):
    invs = db.query(Investigation).order_by(Investigation.created_at.desc()).offset(offset).limit(limit).all()
    results = []
    for i in invs:
        try:
            report_dict = json.loads(i.report_data or "{}")
        except Exception:
            report_dict = {}
        try:
            traces_list = json.loads(i.agent_traces or "[]")
        except Exception:
            traces_list = []

        results.append({
            "id": i.id,
            "investigation_id": i.investigation_id,
            "title": i.title,
            "status": i.status,
            "severity": i.severity,
            "summary": i.summary,
            "created_at": i.created_at,
            "updated_at": i.updated_at,
            "total_steps": len(traces_list),
            "validation_status": report_dict.get("validation_status", "UNKNOWN")
        })
    return results

@router.get("/{investigation_id}")
def get_investigation_detail(investigation_id: str, db: Session = Depends(get_db)):
    i = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
    if not i:
        raise HTTPException(status_code=404, detail="Investigation not found")

    try:
        traces = json.loads(i.agent_traces or "[]")
    except Exception:
        traces = []
    try:
        report = json.loads(i.report_data or "{}")
    except Exception:
        report = {}

    return {
        "id": i.id,
        "investigation_id": i.investigation_id,
        "title": i.title,
        "status": i.status,
        "trigger_alert_id": i.trigger_alert_id,
        "severity": i.severity,
        "summary": i.summary,
        "created_at": i.created_at,
        "updated_at": i.updated_at,
        "agent_traces": traces,
        "report": report
    }

@router.get("/{investigation_id}/trace")
def get_investigation_trace(investigation_id: str, db: Session = Depends(get_db)):
    i = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
    if not i:
        raise HTTPException(status_code=404, detail="Investigation not found")
    try:
        traces = json.loads(i.agent_traces or "[]")
    except Exception:
        traces = []
    return {"investigation_id": investigation_id, "traces": traces}

@router.get("/{investigation_id}/report")
def get_investigation_report(investigation_id: str, db: Session = Depends(get_db)):
    i = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
    if not i:
        raise HTTPException(status_code=404, detail="Investigation not found")
    try:
        report = json.loads(i.report_data or "{}")
    except Exception:
        report = {}
    return report

@router.get("/{investigation_id}/report/pdf")
def export_investigation_pdf(investigation_id: str, db: Session = Depends(get_db)):
    i = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
    if not i:
        raise HTTPException(status_code=404, detail="Investigation not found")
    
    try:
        report = json.loads(i.report_data or "{}")
    except Exception:
        report = {}

    if not report:
        raise HTTPException(status_code=400, detail="Report data is not yet generated for this investigation.")

    pdf_path = os.path.join(PDF_STORAGE_DIR, f"{investigation_id}_report.pdf")
    generate_incident_pdf(report, pdf_path)

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"SENTINEL_AI_Report_{investigation_id}.pdf"
    )

@router.get("/{investigation_id}/stream")
async def stream_investigation_sse(investigation_id: str, db: Session = Depends(get_db)):
    """
    Server-Sent Events (SSE) streaming endpoint for live agent trace updates.
    """
    i = db.query(Investigation).filter(Investigation.investigation_id == investigation_id).first()
    if not i:
        raise HTTPException(status_code=404, detail="Investigation not found")

    try:
        traces = json.loads(i.agent_traces or "[]")
    except Exception:
        traces = []

    async def event_generator():
        yield f"data: {json.dumps({'type': 'INIT', 'investigation_id': investigation_id, 'status': i.status})}\n\n"
        await asyncio.sleep(0.1)

        for step in traces:
            yield f"data: {json.dumps({'type': 'AGENT_STEP', 'step': step})}\n\n"
            await asyncio.sleep(0.3)

        yield f"data: {json.dumps({'type': 'COMPLETE', 'investigation_id': investigation_id})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")
