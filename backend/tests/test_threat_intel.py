from app.threat_intel.service import ThreatIntelService

def test_threat_intel_known_malicious():
    service = ThreatIntelService()
    res = service.lookup_indicator("198.51.100.45", "IP")
    assert res["indicator"] == "198.51.100.45"
    assert res["is_malicious"] is True
    assert res["reputation_score"] > 80.0
    assert res["is_simulated"] is True

def test_threat_intel_benign_dns():
    service = ThreatIntelService()
    res = service.lookup_indicator("8.8.8.8", "IP")
    assert res["indicator"] == "8.8.8.8"
    assert res["is_malicious"] is False
    assert res["reputation_score"] == 0.0

def test_threat_intel_caching():
    service = ThreatIntelService()
    res1 = service.lookup_indicator("203.0.113.19", "IP")
    res2 = service.lookup_indicator("203.0.113.19", "IP")
    assert res1 == res2
