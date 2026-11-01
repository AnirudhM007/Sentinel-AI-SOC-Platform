from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.scenarios.loader import SCENARIOS_META, load_scenario

router = APIRouter(prefix="/scenarios", tags=["Scenarios"])

@router.get("")
def list_scenarios():
    return list(SCENARIOS_META.values())

@router.post("/load/{scenario_id}")
def trigger_load_scenario(scenario_id: str, db: Session = Depends(get_db)):
    try:
        res = load_scenario(scenario_id, db)
        return {"status": "success", "result": res}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load scenario: {str(e)}")
