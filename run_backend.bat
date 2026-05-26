@echo off
setlocal
cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
    echo Khong tim thay venv\Scripts\python.exe
    echo Hay tao venv va cai dependencies truoc.
    pause
    exit /b 1
)

echo Dang chay backend FastAPI...
"venv\Scripts\python.exe" -m uvicorn backend.main:app --reload --port 8000
pause
