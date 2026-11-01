from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from app.config import settings

router = APIRouter(prefix="/settings", tags=["Settings"])

class SettingsUpdateRequest(BaseModel):
    mock_mode: Optional[bool] = None
    llm_provider: Optional[str] = None
    openai_model: Optional[str] = None
    openai_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    brute_force_threshold: Optional[int] = None
    time_window_minutes: Optional[int] = None

@router.get("")
def get_current_settings():
    return {
        "project_name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "mock_mode": settings.MOCK_MODE,
        "llm_provider": settings.LLM_PROVIDER,
        "openai_model": settings.OPENAI_MODEL,
        "has_openai_key": bool(settings.OPENAI_API_KEY),
        "has_abuseipdb_key": bool(settings.ABUSEIPDB_API_KEY),
        "has_virustotal_key": bool(settings.VIRUSTOTAL_API_KEY),
        "brute_force_threshold": settings.BRUTE_FORCE_THRESHOLD,
        "time_window_minutes": settings.TIME_WINDOW_MINUTES,
        "max_investigation_loops": settings.MAX_INVESTIGATION_LOOPS,
        "max_upload_size_mb": settings.MAX_UPLOAD_SIZE_MB
    }

@router.post("")
def update_settings(req: SettingsUpdateRequest):
    if req.mock_mode is not None:
        settings.MOCK_MODE = req.mock_mode
    if req.llm_provider is not None:
        settings.LLM_PROVIDER = req.llm_provider
    if req.openai_model is not None:
        settings.OPENAI_MODEL = req.openai_model
    if req.openai_api_key is not None and req.openai_api_key != "":
        settings.OPENAI_API_KEY = req.openai_api_key
    if req.abuseipdb_api_key is not None and req.abuseipdb_api_key != "":
        settings.ABUSEIPDB_API_KEY = req.abuseipdb_api_key
    if req.virustotal_api_key is not None and req.virustotal_api_key != "":
        settings.VIRUSTOTAL_API_KEY = req.virustotal_api_key
    if req.brute_force_threshold is not None:
        settings.BRUTE_FORCE_THRESHOLD = req.brute_force_threshold
    if req.time_window_minutes is not None:
        settings.TIME_WINDOW_MINUTES = req.time_window_minutes

    return {"status": "success", "message": "Settings updated successfully", "settings": get_current_settings()}
