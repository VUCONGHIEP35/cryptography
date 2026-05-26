@echo off
setlocal
cd /d "%~dp0"
set "APP_DIR=%~dp0"

set "PY_CMD="
where python >nul 2>&1 && set "PY_CMD=python"
if not defined PY_CMD where py >nul 2>&1 && set "PY_CMD=py -3.12"

if not defined PY_CMD (
    echo Khong tim thay python hoac py tren may.
    echo Hay cai Python 3.12 truoc khi chay script nay.
    pause
    exit /b 1
)

if not exist "venv\Scripts\python.exe" (
    echo Dang tao venv...
    %PY_CMD% -m venv venv
    if errorlevel 1 (
        echo Tao venv that bai.
        pause
        exit /b 1
    )
)

echo Dang nang cap pip va cai dependencies...
"venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 (
    echo Cap nhat pip that bai.
    pause
    exit /b 1
)

"venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo Cai dependencies that bai.
    pause
    exit /b 1
)

echo Dang mo backend...
start "Backend" /D "%APP_DIR%" cmd /k ""venv\Scripts\python.exe" -m uvicorn backend.main:app --reload --port 8000"

echo Dang mo frontend...
start "Frontend" /D "%APP_DIR%" cmd /k ""venv\Scripts\python.exe" -m streamlit run frontend/app.py"

echo Da mo ca backend va frontend.
pause