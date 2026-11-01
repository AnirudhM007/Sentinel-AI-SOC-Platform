from fastapi import APIRouter
from app.api.logs import router as logs_router
from app.api.alerts import router as alerts_router
from app.api.investigations import router as investigations_router
from app.api.dashboard import router as dashboard_router
from app.api.threat_intel import router as threat_intel_router
from app.api.scenarios import router as scenarios_router
from app.api.settings import router as settings_router

api_router = APIRouter()

api_router.include_router(dashboard_router)
api_router.include_router(logs_router)
api_router.include_router(alerts_router)
api_router.include_router(investigations_router)
api_router.include_router(threat_intel_router)
api_router.include_router(scenarios_router)
api_router.include_router(settings_router)

__all__ = ["api_router"]
