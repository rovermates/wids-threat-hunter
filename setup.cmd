@echo off
setlocal
cd /d "%~dp0"
py -3.12 -m venv .venv
if errorlevel 1 goto fail
.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
if errorlevel 1 goto fail
.venv\Scripts\python.exe smoke_check.py
if errorlevel 1 goto fail
echo Setup complete. Run start.cmd and open http://127.0.0.1:8000
pause
exit /b 0
:fail
echo Setup failed. Read the error above and README.md.
pause
exit /b 1
