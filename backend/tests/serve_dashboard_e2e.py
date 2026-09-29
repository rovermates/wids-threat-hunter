"""An isolated, disposable server for browser integration tests."""
from pathlib import Path
import tempfile

import uvicorn

from backend.app import create_app
from backend.config import DashboardSettings


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="wids-e2e-") as directory:
        uvicorn.run(create_app(DashboardSettings(state_dir=Path(directory))), host="127.0.0.1", port=8011)
