import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
import httpx
from app.config import settings
from app.threat_intel.mock_db import MOCK_THREAT_DATABASE
from app.models.threat_intel import ThreatIntel
from app.database import SessionLocal

logger = logging.getLogger("sentinel.threat_intel")

class ThreatIntelService:
    def __init__(self):
        self.memory_cache: Dict[str, Dict[str, Any]] = {}

    def lookup_indicator(self, indicator: str, indicator_type: str = "IP") -> Dict[str, Any]:
        """
        Retrieves threat intelligence for an IP or domain.
        Checks in-memory cache -> DB cache -> Live API (if configured) -> Mock Threat DB fallback.
        """
        indicator_clean = indicator.strip()
        if not indicator_clean or indicator_clean in ["127.0.0.1", "localhost", "::1", "-", ""]:
            return {
                "indicator": indicator_clean,
                "indicator_type": indicator_type,
                "reputation_score": 0.0,
                "is_malicious": False,
                "source": "INTERNAL_LOCAL",
                "is_simulated": False,
                "summary": "Local loopback or unassigned indicator; benign.",
                "details": {"category": "Loopback / Internal"}
            }

        # 1. Check in-memory cache
        if indicator_clean in self.memory_cache:
            return self.memory_cache[indicator_clean]

        # 2. Check Database cache
        db = SessionLocal()
        try:
            cached = db.query(ThreatIntel).filter(ThreatIntel.indicator == indicator_clean).first()
            if cached:
                res = {
                    "indicator": cached.indicator,
                    "indicator_type": cached.indicator_type,
                    "reputation_score": cached.reputation_score,
                    "is_malicious": cached.is_malicious,
                    "source": cached.source,
                    "is_simulated": cached.is_simulated,
                    "details": json.loads(cached.raw_response or "{}"),
                    "cached_at": cached.cached_at
                }
                res["summary"] = self._build_summary(res)
                self.memory_cache[indicator_clean] = res
                return res
        except Exception as e:
            logger.warning(f"Error checking threat intel DB cache: {e}")
        finally:
            db.close()

        # 3. Live API query if AbuseIPDB API key is provided and indicator is IP
        if settings.ABUSEIPDB_API_KEY and indicator_type == "IP" and not self._is_private_ip(indicator_clean):
            try:
                live_res = self._query_abuseipdb(indicator_clean)
                if live_res:
                    self._persist_cache(live_res)
                    self.memory_cache[indicator_clean] = live_res
                    return live_res
            except Exception as e:
                logger.warning(f"AbuseIPDB query failed for {indicator_clean}: {e}")

        # 4. Fallback to realistic mock database
        mock_data = MOCK_THREAT_DATABASE.get(indicator_clean)
        if mock_data:
            res = {
                "indicator": indicator_clean,
                "indicator_type": indicator_type,
                "reputation_score": mock_data["reputation_score"],
                "is_malicious": mock_data["is_malicious"],
                "source": "SIMULATED_INTELLIGENCE_FEED",
                "is_simulated": True,
                "details": mock_data,
                "cached_at": datetime.utcnow()
            }
        else:
            # Unknown indicator: do not label malicious merely because it has no reputation data
            is_priv = self._is_private_ip(indicator_clean)
            res = {
                "indicator": indicator_clean,
                "indicator_type": indicator_type,
                "reputation_score": 0.0,
                "is_malicious": False,
                "source": "SIMULATED_INTELLIGENCE_FEED",
                "is_simulated": True,
                "details": {
                    "category": "Private Enterprise IP" if is_priv else "Unrated Public IP",
                    "reports_count": 0,
                    "note": "No adverse threat intelligence reports found in feed."
                },
                "cached_at": datetime.utcnow()
            }

        res["summary"] = self._build_summary(res)
        self._persist_cache(res)
        self.memory_cache[indicator_clean] = res
        return res

    def _query_abuseipdb(self, ip: str) -> Optional[Dict[str, Any]]:
        headers = {
            "Key": settings.ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        with httpx.Client(timeout=4.0) as client:
            resp = client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = float(data.get("abuseConfidenceScore", 0.0))
                return {
                    "indicator": ip,
                    "indicator_type": "IP",
                    "reputation_score": score,
                    "is_malicious": score >= 50.0,
                    "source": "ABUSEIPDB_LIVE",
                    "is_simulated": False,
                    "details": {
                        "category": data.get("usageType", "Public IP"),
                        "country": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "reports_count": data.get("totalReports", 0),
                        "last_reported": data.get("lastReportedAt")
                    },
                    "cached_at": datetime.utcnow()
                }
        return None

    def _is_private_ip(self, ip: str) -> bool:
        return (
            ip.startswith("10.") or 
            ip.startswith("192.168.") or 
            ip.startswith("172.16.") or 
            ip.startswith("172.17.") or 
            ip.startswith("172.31.") or 
            ip == "127.0.0.1"
        )

    def _build_summary(self, res: Dict[str, Any]) -> str:
        sim_tag = "[SIMULATED]" if res.get("is_simulated") else "[LIVE]"
        if res.get("is_malicious"):
            return f"{sim_tag} Host {res['indicator']} has a High Malicious Reputation ({res['reputation_score']}/100). Category: {res.get('details', {}).get('category', 'Threat')}."
        return f"{sim_tag} Host {res['indicator']} shows no malicious history (Score: {res['reputation_score']}/100)."

    def _persist_cache(self, data: Dict[str, Any]):
        db = SessionLocal()
        try:
            existing = db.query(ThreatIntel).filter(ThreatIntel.indicator == data["indicator"]).first()
            if not existing:
                cached_obj = ThreatIntel(
                    indicator=data["indicator"],
                    indicator_type=data.get("indicator_type", "IP"),
                    reputation_score=data.get("reputation_score", 0.0),
                    is_malicious=data.get("is_malicious", False),
                    source=data.get("source", "MOCK_FEED"),
                    is_simulated=data.get("is_simulated", True),
                    raw_response=json.dumps(data.get("details", {})),
                    cached_at=datetime.utcnow()
                )
                db.add(cached_obj)
                db.commit()
        except Exception as e:
            db.rollback()
            logger.warning(f"Failed to persist threat intel record: {e}")
        finally:
            db.close()

threat_intel_service = ThreatIntelService()
