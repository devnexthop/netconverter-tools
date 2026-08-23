@echo off
REM Check Point audit data collection - Windows helper (v1.5.6)
cd /d "%~dp0"

echo ============================================================
echo  NetConverter - Check Point Management API Collector v1.5.6
echo  Read-only. Does not change policies or install anything.
echo ============================================================
echo.

set /p MGMT_IP=Management server IP: 
set /p USERNAME=API username: 
set /p PASSWORD=API password: 
set /p PORT=API port [4434]: 
if "%PORT%"=="" set PORT=4434

echo.
echo Installing Python dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo pip install failed. See INSTALL_PYTHON_WINDOWS.md
    pause
    exit /b 1
)

echo.
echo Starting collection (full-objects + where-used + verify-export)...
python checkpoint_collect_data.py --mgmt-ip %MGMT_IP% --username %USERNAME% --password "%PASSWORD%" --port %PORT% --output . --full-objects --where-used --verify-export

echo.
echo Done. Send ONLY the checkpoint_audit_*.zip file to NextHop.
pause
