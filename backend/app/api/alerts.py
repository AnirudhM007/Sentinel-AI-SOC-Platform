import json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from app.database import get_db
from app.models.alert import Alert
from app.models.log_event import LogEvent
from app.schemas.alert_schema import AlertRead

router = APIRouter(prefix="/alerts", tags=["Alerts"])

def _format_alert(alt: Alert) -> Dict[str, Any]:
    try:
        t_ids = json.loads(alt.triggering_event_ids or "[]")
    except Exception:
        t_ids = []
    try:
        r_fields = json.loads(alt.relevant_fields or "{}")
    except Exception:
        r_fields = {}

    return {
        "id": alt.id,
        "alert_id": alt.alert_id,
        "title": alt.title,
        "detection_type": alt.detection_type,
        "rule_id": alt.rule_id,
        "severity": alt.severity,
        "description": alt.description,
        "confidence": alt.confidence,
        "triggering_event_ids": t_ids,
        "relevant_fields": r_fields,
        "status": alt.status,
        "timestamp": alt.timestamp,
        "investigation_id": alt.investigation_id
    }

@router.get("", response_model=List[AlertRead])
def get_alerts(
    severity: Optional[str] = Query(None),
    detection_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity.upper())
    if detection_type:
        query = query.filter(Alert.detection_type == detection_type.upper())
    if status:
        query = query.filter(Alert.status == status.upper())

    alerts = query.order_by(Alert.timestamp.desc()).offset(offset).limit(limit).all()
    return [_format_alert(a) for a in alerts]

@router.get("/{alert_id}")
def get_alert_detail(alert_id: str, db: Session = Depends(get_db)):
    alt = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alt:
        raise HTTPException(status_code=404, detail="Alert not found")

    fmt = _format_alert(alt)
    # Fetch triggering events
    trigger_events = []
    if fmt["triggering_event_ids"]:
        events = db.query(LogEvent).filter(LogEvent.event_id.in_(fmt["triggering_event_ids"])).all()
        trigger_events = [
            {
                "event_id": e.event_id,
                "timestamp": str(e.timestamp),
                "hostname": e.hostname,
                "username": e.username,
                "source_ip": e.source_ip,
                "destination_ip": e.destination_ip,
                "event_type": e.event_type,
                "severity": e.severity,
                "raw_event": e.raw_event
            }
            for e in events
        ]

    fmt["triggering_events"] = trigger_events
    return fmt
