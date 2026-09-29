"""One local background job at a time; previous results remain readable."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import logging
from threading import Lock
from uuid import uuid4

from backend.dashboard.analysis import analyze_capture
from backend.dashboard.model_info import load_model_info
from backend.dashboard.store import DashboardStore

logger = logging.getLogger(__name__)


class BusyError(ValueError):
    pass


class DashboardService:
    def __init__(self, settings):
        self.settings = settings
        self.store = DashboardStore(settings.state_dir / "dashboard.sqlite3")
        self.model_info = load_model_info(settings.model_path)
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="wids-analysis")
        self.lock = Lock()
        self.jobs = {}
        self.active_id = None
        self.upload_dir = settings.state_dir / "uploads"
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    def reserve(self, filename):
        with self.lock:
            if self.active_id:
                raise BusyError("A capture is already processing. Wait for it to finish.")
            while len(self.jobs) >= 100:
                self.jobs.pop(next(iter(self.jobs)))
            job_id = uuid4().hex
            job = {"id": job_id, "filename": filename, "status": "receiving", "processed_packets": 0,
                   "error": None, "created_at": datetime.now(timezone.utc).isoformat()}
            self.jobs[job_id] = job
            self.active_id = job_id
            return dict(job)

    def get_job(self, job_id):
        with self.lock:
            job = self.jobs.get(job_id)
            return dict(job) if job else None

    def active_job(self):
        with self.lock:
            return dict(self.jobs[self.active_id]) if self.active_id else None

    def update(self, job_id, **values):
        with self.lock:
            self.jobs[job_id].update(values)

    def fail(self, job_id, message):
        with self.lock:
            self.jobs[job_id].update(status="failed", error=message)
            if self.active_id == job_id:
                self.active_id = None

    def submit(self, job_id, path, variant):
        self.update(job_id, status="queued")
        self.executor.submit(self._run, job_id, path, variant)

    def _run(self, job_id, path, variant):
        self.update(job_id, status="processing")
        capture, error = None, None
        try:
            capture = analyze_capture(path, filename=self.get_job(job_id)["filename"], variant=variant,
                analysis_id=job_id, settings=self.settings, store=self.store,
                progress=lambda count: self.update(job_id, processed_packets=count))
        except ValueError as exc:
            error = str(exc)
        except Exception:
            logger.exception("Capture processing failed for job %s", job_id)
            error = "Processing failed. Check the server log and model/dependency setup, then retry."
        finally:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                logger.exception("Temporary upload cleanup failed for job %s", job_id)
        if capture is not None:
            with self.lock:
                self.jobs[job_id].update(status="completed", analysis_id=capture["id"],
                    processed_packets=capture["total_packets"])
                self.active_id = None
        else:
            self.fail(job_id, error)

    def close(self):
        self.executor.shutdown(wait=True)
