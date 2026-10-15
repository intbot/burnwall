@echo off
rem Starts the local Cursor Usage API on http://127.0.0.1:8787 (logs to data\server.log).
rem HOST and PORT override the address, e.g. set PORT=9000 before running it.
cd /d "%~dp0"
if not exist data mkdir data
if "%HOST%"=="" set HOST=127.0.0.1
if "%PORT%"=="" set PORT=8787
.venv\Scripts\python.exe -m uvicorn app.main:app --host %HOST% --port %PORT% >> data\server.log 2>&1
