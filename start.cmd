@echo off
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
 echo Create the Python environment using the README instructions first.
 pause
 exit /b 1
)
echo Starting the dashboard with the refined v7 default.
echo Open http://127.0.0.1:8000 . Close any older server on that port first.
.venv\Scripts\python.exe -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
pause
