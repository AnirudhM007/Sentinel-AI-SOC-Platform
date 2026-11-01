import json
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.models.log_event import LogEvent
from app.models.alert import Alert
from app.schemas.log_schema import LogEventRead
from app.parsers.normalizer import detect_and_normalize
from app.detection.engine import detection_engine
from app.ml.model import anomaly_detector
from app.config import settings

router = APIRouter(prefix="/logs", tags=["Logs"])

@router.post("/upload")
async def upload_logs(file: UploadFile = File(...), db: Session = Depends(get_db)):
    # File size validation (10 MB limit)
    contents = await file.read()
    if len(contents) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_MB}MB.")

    normalized_events, stats = detect_and_normalize(contents, file.filename or "uploaded_log")

    if not normalized_events:
        return {"status": "success", "message": "No valid log records found to ingest.", "stats": stats, "alerts_generated": 0}

    # Persist events
    for ev in normalized_events:
        db_ev = LogEvent(
            event_id=ev["event_id"],
            timestamp=ev["timestamp"],
            hostname=ev.get("hostname", "unknown"),
            username=ev.get("username", "unknown"),
            source_ip=ev.get("source_ip", ""),
            destination_ip=ev.get("destination_ip", ""),
            event_type=ev.get("event_type", "SYSTEM_LOG"),
            event_id_native=ev.get("event_id_native", ""),
            process_name=ev.get("process_name", ""),
            command_line=ev.get("command_line", ""),
            status=ev.get("status", "UNKNOWN"),
            severity=ev.get("severity", "INFORMATIONAL"),
            raw_event=ev.get("raw_event", ""),
            file_source=file.filename or "upload"
        )
        db.add(db_ev)

    # Run detection rules & ML anomalies
    rule_alerts = detection_engine.run_detection(normalized_events)
    ml_alerts = anomaly_detector.detect_anomalies(normalized_events)
    all_alerts = rule_alerts + ml_alerts

    for alt in all_alerts:
        db_alt = Alert(
            alert_id=alt["alert_id"],
            title=alt["title"],
            detection_type=alt.get("detection_type", "RULE"),
            rule_id=alt.get("rule_id", ""),
            severity=alt.get("severity", "MEDIUM"),
            description=alt["description"],
            confidence=alt.get("confidence", 1.0),
            triggering_event_ids=json.dumps(alt.get("triggering_event_ids", [])),
            relevant_fields=json.dumps(alt.get("relevant_fields", {})),
            status="NEW",
            timestamp=alt.get("timestamp")
        )
        db.add(db_alt)

    db.commit()

    return {
        "status": "success",
        "filename": file.filename,
        "stats": stats,
        "events_ingested": len(normalized_events),
        "alerts_generated": len(all_alerts),
        "rule_alerts_count": len(rule_alerts),
        "ml_alerts_count": len(ml_alerts)
    }

@router.get("", response_model=List[LogEventRead])
def get_logs(
    hostname: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(LogEvent)

    if hostname:
        query = query.filter(LogEvent.hostname.ilike(f"%{hostname}%"))
    if username:
        query = query.filter(LogEvent.username.ilike(f"%{username}%"))
    if source_ip:
        query = query.filter(LogEvent.source_ip.ilike(f"%{source_ip}%"))
    if severity:
        query = query.filter(LogEvent.severity == severity.upper())
    if event_type:
        query = query.filter(LogEvent.event_type == event_type.upper())
    if search:
        query = query.filter(
            (LogEvent.raw_event.ilike(f"%{search}%")) |
            (LogEvent.command_line.ilike(f"%{search}%")) |
            (LogEvent.hostname.ilike(f"%{search}%")) |
            (LogEvent.username.ilike(f"%{search}%"))
        )

    return query.order_by(LogEvent.timestamp.desc()).offset(offset).limit(limit).all()

@router.get("/{event_id}", response_model=LogEventRead)
def get_log_by_id(event_id: str, db: Session = Depends(get_db)):
    ev = db.query(LogEvent).filter(LogEvent.event_id == event_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Log event not found")
    return ev
