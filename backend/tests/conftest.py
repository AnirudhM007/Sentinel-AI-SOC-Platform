import sys
import os

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.database import engine, Base
import app.models  # Registers all models with Base.metadata
from app.ml.train import train_and_initialize_baseline

Base.metadata.create_all(bind=engine)
train_and_initialize_baseline()
