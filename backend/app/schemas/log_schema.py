from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict

class LogEventBase(BaseModel):
    event_id: str
    timestamp: datetime
    hostname: str = "unknown"
    username: str = "unknown"
    source_ip: str = ""
    destination_ip: str = ""
    event_type: str
    event_id_native: str = ""
    process_name: str = ""
    command_line: str = ""
    status: str = "UNKNOWN"
    severity: str = "INFORMATIONAL"
    raw_event: str
    file_source: str = "manual_upload"

class LogEventCreate(LogEventBase):
    pass

class LogEventRead(LogEventBase):
    id: int
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

class LogFilterParams(BaseModel):
    hostname: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    severity: Optional[str] = None
    event_type: Optional[str] = None
    status: Optional[str] = None
    search: Optional[str] = None
    limit: int = 100
    offset: int = 0
