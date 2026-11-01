from typing import List, Dict, Any
from app.config import settings
from app.detection.rules import (
    SSHBruteForceRule,
    SuspiciousSuccessfulAuthRule,
    WindowsLogonBurstRule,
    PrivilegeEscalationRule,
    AccountCreationRule,
    SuspiciousProcessExecutionRule,
    SuspiciousNetworkConnectionRule,
    PasswordSprayingRule
)

class DetectionEngine:
    def __init__(self):
        self.rules = [
            SSHBruteForceRule(threshold=settings.BRUTE_FORCE_THRESHOLD, window_minutes=settings.TIME_WINDOW_MINUTES),
            SuspiciousSuccessfulAuthRule(failure_threshold=3, window_minutes=settings.TIME_WINDOW_MINUTES * 2),
            WindowsLogonBurstRule(threshold=settings.BRUTE_FORCE_THRESHOLD),
            PrivilegeEscalationRule(),
            AccountCreationRule(),
            SuspiciousProcessExecutionRule(),
            SuspiciousNetworkConnectionRule(high_frequency_threshold=8),
            PasswordSprayingRule(unique_users_threshold=3)
        ]

    def run_detection(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Evaluates all deterministic rules against provided events.
        Returns list of generated alert dictionaries.
        """
        all_alerts = []
        for rule in self.rules:
            try:
                rule_alerts = rule.evaluate(events)
                all_alerts.extend(rule_alerts)
            except Exception as e:
                # Never crash the entire pipeline if a single rule fails
                print(f"[DetectionEngine] Error executing {rule.rule_id}: {e}")

        return all_alerts

detection_engine = DetectionEngine()
