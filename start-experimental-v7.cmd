@echo off
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
 echo Python environment missing. Use the project setup instructions first.
 pause
 exit /b 1
)
echo ORIGINAL EXPERIMENTAL V7: retained for comparison; has excessive false alerts.
echo Open http://127.0.0.1:8001 . The normal dashboard now uses refined v7.
set "WIDS_MODEL_PATH=%CD%\backend\models\additional_captures_v7\trained_ensemble.joblib"
set "WIDS_STATE_DIR=%CD%\data\dashboard-v7-experimental"
.venv\Scripts\python.exe -m uvicorn backend.app:app --host 127.0.0.1 --port 8001
pause
