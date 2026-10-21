import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "shadow_map.db"

# Local-only by default. Configure these through environment variables
# when running in a controlled shared environment.
SECRET_KEY = os.environ.get(
    "SHADOW_MAP_SECRET_KEY",
    "local-development-only-change-before-hosting",
)
HOST = os.environ.get("SHADOW_MAP_HOST", "127.0.0.1")
PORT = int(os.environ.get("SHADOW_MAP_PORT", "5000"))

DATA_DIR.mkdir(parents=True, exist_ok=True)
