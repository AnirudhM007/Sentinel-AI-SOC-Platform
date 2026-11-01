import pandas as pd
import numpy as np
from app.ml.features import FEATURE_COLUMNS
from app.ml.model import anomaly_detector

def generate_synthetic_baseline(num_hosts: int = 40) -> pd.DataFrame:
    """
    Generates a realistic baseline dataset of routine, benign enterprise host activity.
    """
    np.random.seed(42)
    records = []
    for i in range(num_hosts):
        records.append({
            "hostname": f"srv-corp-{i:02d}",
            "failed_logins": float(np.random.choice([0, 1, 2], p=[0.75, 0.20, 0.05])),
            "successful_logins": float(np.random.randint(15, 60)),
            "unique_source_ips": float(np.random.choice([1, 2, 3], p=[0.7, 0.2, 0.1])),
            "unique_targeted_users": float(np.random.choice([1, 2], p=[0.85, 0.15])),
            "avg_hour_of_day": float(np.random.normal(13.5, 2.0)),
            "off_hours_ratio": float(np.random.beta(1, 10)),  # Low off hours
            "privilege_event_count": float(np.random.choice([0, 1], p=[0.9, 0.1])),
            "total_event_volume": float(np.random.randint(20, 100))
        })
    return pd.DataFrame(records)

def train_and_initialize_baseline():
    """Initializes the baseline model for anomaly detection."""
    baseline_df = generate_synthetic_baseline(50)
    anomaly_detector.fit_baseline(baseline_df)
    print(f"[ML Init] Isolation Forest trained on {len(baseline_df)} baseline enterprise hosts.")

if __name__ == "__main__":
    train_and_initialize_baseline()
