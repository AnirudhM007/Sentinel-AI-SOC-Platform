import pytest
from fastapi.testclient import TestClient
from app.database import engine, Base
from app import models  # Does NOT overwrite 'app' symbol if we import fastapi_app explicitly
from app.main import app as fastapi_app

Base.metadata.create_all(bind=engine)
client = TestClient(fastapi_app)

def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "SENTINEL AI"

def test_dashboard_summary_endpoint():
    response = client.get("/api/dashboard/summary")
    assert response.status_code == 200
    data = response.json()
    assert "total_events" in data
    assert "severity_distribution" in data

def test_scenarios_listing():
    response = client.get("/api/scenarios")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 5

def test_scenario_loading_and_investigation_flow():
    # 1. Load Scenario 1 (SSH Brute Force)
    load_resp = client.post("/api/scenarios/load/scenario_1")
    assert load_resp.status_code == 200
    load_data = load_resp.json()
    assert load_data["status"] == "success"
    assert load_data["result"]["events_ingested"] > 0
    assert load_data["result"]["alerts_generated"] > 0

    # 2. Verify Alerts created
    alerts_resp = client.get("/api/alerts")
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()
    assert len(alerts) > 0
    target_alert = alerts[0]

    # 3. Start Investigation via LangGraph
    inv_resp = client.post("/api/investigations/start", json={"alert_id": target_alert["alert_id"]})
    assert inv_resp.status_code == 200
    inv_data = inv_resp.json()
    inv_id = inv_data["investigation_id"]
    assert inv_data["status"] == "COMPLETED"
    assert inv_data["report_generated"] is True

    # 4. Check Trace endpoint
    trace_resp = client.get(f"/api/investigations/{inv_id}/trace")
    assert trace_resp.status_code == 200
    assert len(trace_resp.json()["traces"]) >= 6

    # 5. Check Report endpoint
    report_resp = client.get(f"/api/investigations/{inv_id}/report")
    assert report_resp.status_code == 200
    rep = report_resp.json()
    assert "executive_summary" in rep
    assert "mitre_attack_mappings" in rep
