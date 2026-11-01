from fastapi import APIRouter, HTTPException
from app.threat_intel.service import threat_intel_service
from app.schemas.threat_intel_schema import ThreatIntelResult

router = APIRouter(prefix="/threat-intelligence", tags=["Threat Intelligence"])

@router.get("/{indicator}")
def lookup_threat_indicator(indicator: str):
    ind_clean = indicator.strip()
    if not ind_clean:
        raise HTTPException(status_code=400, detail="Indicator string cannot be empty")
    
    ind_type = "IP" if any(c.isdigit() for c in ind_clean) and "." in ind_clean else "DOMAIN"
    res = threat_intel_service.lookup_indicator(ind_clean, ind_type)
    return res
