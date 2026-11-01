import datetime
import pandas as pd
from app.ml.features import extract_features_per_host
from app.ml.model import SecurityAnomalyDetector
from app.ml.train import generate_synthetic_baseline

def test_feature_extraction():
    events = [
        {
            "event_id": "e1",
            "timestamp": datetime.datetime(2026, 10, 31, 23, 0, 0),
            "hostname": "host-alpha",
            "username": "root",
            "source_ip": "1.2.3.4",
            "event_type": "AUTH_FAILURE",
            "event_id_native": "",
            "severity": "LOW"
        },
        {
            "event_id": "e2",
            "timestamp": datetime.datetime(2026, 10, 31, 23, 5, 0),
            "hostname": "host-alpha",
            "username": "admin",
            "source_ip": "1.2.3.4",
            "event_type": "AUTH_SUCCESS",
            "event_id_native": "",
            "severity": "INFORMATIONAL"
        }
    ]
    df, host_map = extract_features_per_host(events)
    assert len(df) == 1
    assert df.iloc[0]["hostname"] == "host-alpha"
    assert df.iloc[0]["failed_logins"] == 1.0
    assert df.iloc[0]["successful_logins"] == 1.0
    assert len(host_map["host-alpha"]) == 2

def test_anomaly_detection_model():
    detector = SecurityAnomalyDetector(contamination=0.1)
    baseline = generate_synthetic_baseline(30)
    detector.fit_baseline(baseline)
    assert detector.is_fitted is True

    # Test anomalous telemetry with massive failed logins in off-hours
    anom_events = [
        {
            "event_id": f"anom-{i}",
            "timestamp": datetime.datetime(2026, 10, 31, 2, 0, 0),
            "hostname": "srv-victim",
            "username": f"user-{i}",
            "source_ip": f"10.0.0.{i}",
            "event_type": "AUTH_FAILURE",
            "event_id_native": "",
            "severity": "LOW"
        }
        for i in range(25)
    ]
    anomalies = detector.detect_anomalies(anom_events)
    assert len(anomalies) >= 1
    assert anomalies[0]["detection_type"] == "ML_ANOMALY"
    assert anomalies[0]["relevant_fields"]["hostname"] == "srv-victim"
