@echo off
setlocal
cd /d "%~dp0"
set "APP_DIR=%~dp0"
set "VENV_DIR=%APP_DIR%venv"
set "VENV_PY=%VENV_DIR%\Scripts\python.exe"
set "REQ_FILE=%APP_DIR%requirements.lock.txt"

if not exist "%REQ_FILE%" set "REQ_FILE=%APP_DIR%requirements.txt"

set "PY_CMD="
python -c "import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)" >nul 2>&1
if not errorlevel 1 set "PY_CMD=python"
if not defined PY_CMD py -3 -c "import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)" >nul 2>&1 && set "PY_CMD=py -3"

if not defined PY_CMD (
    echo Khong tim thay python hoac py tren may.
    echo Hay cai Python 3 tren may truoc khi chay script nay.
    pause
    exit /b 1
)

if not exist "%VENV_PY%" (
    echo Chua co venv, dang tao moi...
    call :create_venv
    if errorlevel 1 (
        echo Tao venv that bai.
        pause
        exit /b 1
    )
)

if exist "%VENV_PY%" (
    "%VENV_PY%" -c "import sys" >nul 2>&1
    if errorlevel 1 (
        echo Venv cu bi hong hoac tro den Python khong con ton tai.
        echo Dang xoa va tao lai venv...
        if exist "%VENV_DIR%" rmdir /s /q "%VENV_DIR%"
        call :create_venv
        if errorlevel 1 (
            echo Tao venv that bai.
            pause
            exit /b 1
        )
    )
)

echo Dang cai dependencies...
"%VENV_PY%" -m pip install -r "%REQ_FILE%"
if errorlevel 1 (
    echo Cai dependencies that bai.
    pause
    exit /b 1
)

echo Dang chay frontend Streamlit...
"%VENV_PY%" -m streamlit run frontend/app.py
pause
exit /b 0

:create_venv
call %PY_CMD% -m venv "%VENV_DIR%"
if errorlevel 1 exit /b 1
exit /b 0
