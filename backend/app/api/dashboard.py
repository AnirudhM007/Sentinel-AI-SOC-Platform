import json
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.models.log_event import LogEvent
from app.models.alert import Alert
from app.models.investigation import Investigation

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/summary")
def get_dashboard_summary(db: Session = Depends(get_db)):
    # 1. Total events count
    total_events = db.query(func.count(LogEvent.id)).scalar() or 0

    # 2. Investigations counts
    total_investigations = db.query(func.count(Investigation.id)).scalar() or 0
    active_investigations = db.query(func.count(Investigation.id)).filter(Investigation.status == "IN_PROGRESS").scalar() or 0
    critical_incidents = db.query(func.count(Investigation.id)).filter(Investigation.severity == "CRITICAL").scalar() or 0
    high_incidents = db.query(func.count(Investigation.id)).filter(Investigation.severity == "HIGH").scalar() or 0

    # 3. Anomaly count & Alert counts
    anomaly_count = db.query(func.count(Alert.id)).filter(Alert.detection_type == "ML_ANOMALY").scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0

    # 4. Severity breakdown across alerts
    sev_rows = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    severity_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    for s_name, count in sev_rows:
        s_upper = (s_name or "INFORMATIONAL").upper()
        if s_upper in severity_distribution:
            severity_distribution[s_upper] = count

    # 5. Top affected hosts
    top_hosts_rows = (
        db.query(LogEvent.hostname, func.count(LogEvent.id))
        .filter(LogEvent.hostname != "unknown")
        .group_by(LogEvent.hostname)
        .order_by(func.count(LogEvent.id).desc())
        .limit(5)
        .all()
    )
    top_affected_hosts = [{"hostname": h, "event_count": count} for h, count in top_hosts_rows]

    # 6. Recent alerts
    recent_alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(6).all()
    recent_alerts_formatted = []
    for a in recent_alerts:
        try:
            rel = json.loads(a.relevant_fields or "{}")
        except Exception:
            rel = {}
        recent_alerts_formatted.append({
            "alert_id": a.alert_id,
            "title": a.title,
            "severity": a.severity,
            "detection_type": a.detection_type,
            "rule_id": a.rule_id,
            "timestamp": str(a.timestamp),
            "relevant_fields": rel
        })

    # 7. Recent investigations
    recent_invs = db.query(Investigation).order_by(Investigation.created_at.desc()).limit(5).all()
    recent_invs_formatted = [
        {
            "investigation_id": i.investigation_id,
            "title": i.title,
            "status": i.status,
            "severity": i.severity,
            "summary": i.summary,
            "created_at": str(i.created_at)
        }
        for i in recent_invs
    ]

    # 8. Event activity timeline aggregation
    # Query last 100 events to construct chronological trend buckets
    events_sample = (
        db.query(LogEvent.timestamp, LogEvent.event_type)
        .order_by(LogEvent.timestamp.asc())
        .limit(150)
        .all()
    )
    
    activity_buckets = {}
    for ts, ev_type in events_sample:
        if ts:
            time_key = ts.strftime("%H:%M")
            if time_key not in activity_buckets:
                activity_buckets[time_key] = {"time": time_key, "total": 0, "auth_failures": 0, "normal": 0}
            activity_buckets[time_key]["total"] += 1
            if ev_type == "AUTH_FAILURE":
                activity_buckets[time_key]["auth_failures"] += 1
            else:
                activity_buckets[time_key]["normal"] += 1

    activity_chart_data = list(activity_buckets.values())[-12:]

    return {
        "total_events": total_events,
        "total_investigations": total_investigations,
        "active_investigations": active_investigations,
        "critical_incidents": critical_incidents,
        "high_incidents": high_incidents,
        "anomaly_count": anomaly_count,
        "total_alerts": total_alerts,
        "severity_distribution": severity_distribution,
        "top_affected_hosts": top_affected_hosts,
        "recent_alerts": recent_alerts_formatted,
        "recent_investigations": recent_invs_formatted,
        "event_activity_chart": activity_chart_data
    }
