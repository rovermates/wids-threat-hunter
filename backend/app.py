"""Run locally: python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000."""
from contextlib import asynccontextmanager
from pathlib import Path
import re
import shutil
from typing import Literal, Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.background import BackgroundTask
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.config import DashboardSettings, DATA_DIR
from backend.core.pcap_parser import PcapError, resolve_tshark
from backend.dashboard.exports import create_export
from backend.dashboard.rules import generate_rules
from backend.dashboard.service import BusyError, DashboardService
from backend.dashboard.store import AnalysisChanged


class UploadLimitMiddleware:
    """Cap multipart bodies before disk spooling, including chunked requests."""
    def __init__(self, app, limit):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") != "POST":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        length = headers.get(b"content-length")
        if length:
            try:
                if int(length) > self.limit:
                    return await JSONResponse({"detail": "Upload exceeds the configured size limit."}, 413)(scope, receive, send)
            except ValueError:
                return await JSONResponse({"detail": "Invalid Content-Length."}, 400)(scope, receive, send)
        consumed = 0

        async def bounded_receive():
            nonlocal consumed
            message = await receive()
            consumed += len(message.get("body", b""))
            if consumed > self.limit:
                raise StarletteHTTPException(413, "Upload exceeds the configured size limit.")
            return message

        await self.app(scope, bounded_receive, send)


def create_app(settings=None):
    settings = settings or DashboardSettings()

    @asynccontextmanager
    async def lifespan(application):
        application.state.service = DashboardService(settings)
        try:
            yield
        finally:
            application.state.service.close()

    application = FastAPI(title="WIDS Threat Hunter", version="4.0.0", lifespan=lifespan)
    application.add_middleware(UploadLimitMiddleware, limit=settings.max_upload_bytes + 64 * 1024)

    @application.exception_handler(AnalysisChanged)
    async def analysis_changed(_, exc):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @application.exception_handler(BusyError)
    async def busy(_, exc):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    def service():
        return application.state.service

    def require_model():
        if not service().model_info["ready"]:
            raise HTTPException(503, service().model_info["error"] or "Model unavailable.")

    @application.get("/api/health")
    def health():
        try:
            resolve_tshark()
            pcap_ready = True
        except PcapError:
            pcap_ready = False
        return {"status": "ok", "model_ready": service().model_info["ready"], "pcap_available": pcap_ready,
                "max_upload_bytes": settings.max_upload_bytes, "max_packets": settings.max_packets,
                "mode": "offline_capture", "active_job": service().active_job()}

    @application.post("/api/upload", status_code=202)
    def upload(file: UploadFile = File(...), variant: Optional[Literal["CLS", "ATK"]] = Form(None)):
        require_model()
        filename = (file.filename or "capture").replace("\\", "/").rsplit("/", 1)[-1][:200]
        suffix = Path(filename).suffix.lower()
        if suffix not in {".csv", ".pcap", ".pcapng"}:
            raise HTTPException(415, "Choose a .pcap, .pcapng, or AWID .csv file.")
        matched = re.fullmatch(r"AWID-(CLS|ATK)-R-(Trn|Tst)\.csv", filename, re.I)
        detected = matched[1].upper() if matched else None
        if variant and detected and variant != detected:
            raise HTTPException(422, "The selected CSV variant conflicts with the filename.")
        variant = variant or detected or "CLS"
        job = service().reserve(filename)
        path = service().upload_dir / (job["id"] + suffix)
        try:
            size = 0
            with path.open("xb") as stream:
                while chunk := file.file.read(1024 * 1024):
                    size += len(chunk)
                    if size > settings.max_upload_bytes:
                        raise HTTPException(413, "Upload exceeds the configured size limit. Split the capture and retry.")
                    stream.write(chunk)
            if size == 0:
                raise HTTPException(422, "The uploaded file is empty.")
            service().submit(job["id"], path, variant)
        except Exception as exc:
            path.unlink(missing_ok=True)
            service().fail(job["id"], str(getattr(exc, "detail", "Unable to save the upload.")))
            raise
        finally:
            file.file.close()
        return {"id": job["id"], "status": "accepted", "status_url": "/api/jobs/" + job["id"]}

    @application.post("/api/sample", status_code=202)
    def sample():
        require_model()
        job = service().reserve("sample_awid.csv")
        path = service().upload_dir / (job["id"] + ".csv")
        try:
            shutil.copyfile(DATA_DIR / "sample_awid.csv", path)
            service().submit(job["id"], path, "CLS")
        except Exception:
            path.unlink(missing_ok=True)
            service().fail(job["id"], "Unable to load data/sample_awid.csv.")
            raise HTTPException(503, "The bundled sample is unavailable.")
        return {"id": job["id"], "status": "accepted", "status_url": "/api/jobs/" + job["id"]}

    @application.get("/api/jobs/{job_id}")
    def job_status(job_id: str):
        job = service().get_job(job_id)
        if job is None:
            raise HTTPException(404, "Job not found. Jobs expire after a restart or 100 newer uploads.")
        return job

    @application.get("/api/metrics")
    def metrics():
        capture = service().store.capture()
        return {"capture": capture, "model": service().model_info,
                "needs_reanalysis": bool(capture and capture.get("model_artifact_sha256") != service().model_info.get("artifact_sha256"))}

    @application.get("/api/traffic")
    def traffic(analysis_id: Optional[str] = None):
        return service().store.traffic(expected=analysis_id)

    @application.get("/api/threats")
    def threats(analysis_id: Optional[str] = None, limit: int = Query(100, ge=1, le=500)):
        return service().store.threats(expected=analysis_id, limit=limit)

    @application.get("/api/packets")
    def packets(page: int = Query(1, ge=1), page_size: int = Query(10, ge=1, le=100),
                mac: str = Query("", max_length=64), attack_type: Literal["", "suspected_evil_twin", "suspected_rogue_ap", "not_evaluated", "no_detection"] = "",
                severity: Literal["", "low", "medium", "high"] = "", analysis_id: Optional[str] = None):
        return service().store.packets(page=page, page_size=page_size, expected=analysis_id,
                                       mac=mac, attack_type=attack_type, severity=severity)

    @application.get("/api/rules")
    def rules(analysis_id: str, iptables: bool = False, hostapd: bool = False):
        feed = service().store.threats(expected=analysis_id)
        return {"analysis_id": analysis_id, **generate_rules(feed["items"], iptables=iptables, hostapd=hostapd)}

    @application.get("/api/export")
    def export(analysis_id: str, format: Literal["json", "csv"] = "json", mac: str = Query("", max_length=64),
               attack_type: Literal["", "suspected_evil_twin", "suspected_rogue_ap", "not_evaluated", "no_detection"] = "",
               severity: Literal["", "low", "medium", "high"] = ""):
        path = create_export(service().store, settings.state_dir, format=format, expected=analysis_id,
                             mac=mac, attack_type=attack_type, severity=severity)
        return FileResponse(path, media_type="application/json" if format == "json" else "text/csv",
                            filename=f"wids-{analysis_id[:8]}.{format}", background=BackgroundTask(path.unlink, missing_ok=True))

    if settings.frontend_dir.is_dir():
        application.mount("/assets", StaticFiles(directory=settings.frontend_dir / "assets"), name="assets")

        @application.get("/", include_in_schema=False)
        def frontend():
            return FileResponse(settings.frontend_dir / "index.html")
    else:
        @application.get("/", include_in_schema=False)
        def not_built():
            return {"message": "Build frontend with npm install && npm run build, then restart the server.", "api_docs": "/docs"}
    return application


app = create_app()
