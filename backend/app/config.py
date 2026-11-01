import os
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "SENTINEL AI"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    DATABASE_URL: str = "sqlite:///./sentinel.db"
    
    # LLM Settings
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "mock") # "mock" or "openai"
    MOCK_MODE: bool = True # Always safe fallback
    
    # Threat Intel APIs
    ABUSEIPDB_API_KEY: Optional[str] = os.getenv("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY", "")
    
    # Detection Thresholds
    BRUTE_FORCE_THRESHOLD: int = 5
    TIME_WINDOW_MINUTES: int = 15
    ANOMALY_CONTAMINATION: float = 0.08
    MAX_INVESTIGATION_LOOPS: int = 2
    
    # Storage & Upload limits
    MAX_UPLOAD_SIZE_MB: int = 10
    
    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()
