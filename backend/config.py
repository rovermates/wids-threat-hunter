"""Project-relative paths, independent of the caller's working directory."""
from pathlib import Path
from dataclasses import dataclass, field
import os

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
AWID_DATA_DIR = DATA_DIR / "raw" / "awid2"
DEFAULT_CHUNK_SIZE = 10_000


@dataclass(frozen=True)
class DashboardSettings:
    model_path: Path = field(default_factory=lambda: Path(os.environ.get(
        "WIDS_MODEL_PATH", PROJECT_ROOT / "backend/models/v7_error_reduction_final/trained_ensemble.joblib")))
    state_dir: Path = field(default_factory=lambda: Path(os.environ.get(
        "WIDS_STATE_DIR", DATA_DIR / "dashboard")))
    max_upload_bytes: int = field(default_factory=lambda: int(os.environ.get(
        "WIDS_MAX_UPLOAD_MB", "64")) * 1024 * 1024)
    max_packets: int = field(default_factory=lambda: int(os.environ.get("WIDS_MAX_PACKETS", "1000000")))
    chunk_size: int = 2000
    frontend_dir: Path = PROJECT_ROOT / "frontend/dist"

    def __post_init__(self):
        if min(self.max_upload_bytes, self.max_packets, self.chunk_size) <= 0:
            raise ValueError("Dashboard limits must be positive")
