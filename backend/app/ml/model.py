import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from app.ml.features import FEATURE_COLUMNS, extract_features_per_host

class SecurityAnomalyDetector:
    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100
        )
        self.is_fitted = False
        self.baseline_means: Dict[str, float] = {}
        self.baseline_stds: Dict[str, float] = {}

    def fit_baseline(self, baseline_df: pd.DataFrame):
        """Fit Isolation Forest on normal baseline telemetry."""
        if baseline_df.empty or len(baseline_df) < 2:
            return
        
        X = baseline_df[FEATURE_COLUMNS].fillna(0).values
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True

        for col in FEATURE_COLUMNS:
            self.baseline_means[col] = float(baseline_df[col].mean())
            self.baseline_stds[col] = float(baseline_df[col].std()) if baseline_df[col].std() > 0 else 1.0

    def detect_anomalies(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extracts host features and detects statistical anomalies using Isolation Forest.
        Returns list of structured ML anomaly alerts.
        """
        if not events:
            return []

        feat_df, host_event_map = extract_features_per_host(events)
        if feat_df.empty:
            return []

        # If model is not yet fitted, fit on the provided telemetry with minimum sample safety
        if not self.is_fitted:
            self.fit_baseline(feat_df)

        if not self.is_fitted or len(feat_df) == 0:
            return []

        X = feat_df[FEATURE_COLUMNS].fillna(0).values
        try:
            X_scaled = self.scaler.transform(X)
            # IsolationForest decision_function: lower score = more anomalous
            raw_scores = self.model.decision_function(X_scaled)
            preds = self.model.predict(X_scaled)
        except Exception:
            return []

        anomalies = []
        for idx, row in feat_df.iterrows():
            is_anomaly = preds[idx] == -1
            # Normalize anomaly score to 0.0 - 1.0 scale (higher = more anomalous)
            # decision_function gives ~[-0.5, 0.5]
            raw_score = raw_scores[idx]
            anomaly_score = float(np.clip(1.0 - (raw_score + 0.5), 0.0, 1.0))

            if is_anomaly or anomaly_score > 0.65:
                host_str = row["hostname"]
                # Identify features contributing most to the anomaly
                contributions = []
                for col in FEATURE_COLUMNS:
                    val = float(row[col])
                    base_mean = self.baseline_means.get(col, 0.0)
                    base_std = self.baseline_stds.get(col, 1.0)
                    z_score = abs(val - base_mean) / base_std
                    if z_score > 1.2 or (val > 0 and base_mean == 0):
                        contributions.append({
                            "feature": col,
                            "observed_value": val,
                            "baseline_mean": round(base_mean, 2),
                            "deviation_z_score": round(z_score, 2)
                        })

                # Sort by deviation
                contributions = sorted(contributions, key=lambda x: x["deviation_z_score"], reverse=True)

                trigger_ids = host_event_map.get(host_str, [])
                last_ts = datetime.utcnow()

                anomalies.append({
                    "alert_id": f"ALT-ML-{uuid.uuid4().hex[:10].upper()}",
                    "title": f"Statistical Telemetry Anomaly on Host '{host_str}'",
                    "detection_type": "ML_ANOMALY",
                    "rule_id": "ML-ISOFOREST-ANOMALY",
                    "severity": "HIGH" if anomaly_score > 0.8 else "MEDIUM",
                    "description": (
                        f"Isolation Forest flagged host '{host_str}' with an anomaly score of {round(anomaly_score, 3)}. "
                        f"Top anomalous dimensions: {', '.join([c['feature'] for c in contributions[:3]]) or 'Volume deviation'}."
                    ),
                    "confidence": round(float(anomaly_score), 2),
                    "triggering_event_ids": trigger_ids[:15],
                    "relevant_fields": {
                        "hostname": host_str,
                        "anomaly_score": round(anomaly_score, 4),
                        "model": "IsolationForest",
                        "top_contributing_features": contributions[:4],
                        "feature_vector": {col: float(row[col]) for col in FEATURE_COLUMNS}
                    },
                    "timestamp": last_ts
                })

        return anomalies

anomaly_detector = SecurityAnomalyDetector()
