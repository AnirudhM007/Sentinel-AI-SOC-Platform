import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import engine, Base
import app.models  # Ensures all models are registered on Base.metadata
from app.api import api_router
from app.ml.train import train_and_initialize_baseline

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Create tables and fit ML baseline
    Base.metadata.create_all(bind=engine)
    train_and_initialize_baseline()
    os.makedirs(os.path.join(os.getcwd(), "storage", "reports"), exist_ok=True)
    yield

    # Shutdown logic if needed

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Autonomous Security Operations & Threat Investigation Platform powered by LangGraph.",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(api_router, prefix=settings.API_V1_STR)

@app.get("/api/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "mode": "mock" if settings.MOCK_MODE else "live",
        "llm_provider": settings.LLM_PROVIDER
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
