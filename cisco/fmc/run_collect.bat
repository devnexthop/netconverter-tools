@echo off
REM Cisco FMC audit data collection - Windows helper (mirrors checkpoint\run_collect.bat)
cd /d "%~dp0"

echo Cisco FMC Audit Collector
echo.

set /p FMC_HOST=FMC IP or hostname: 
set /p FMC_USER=API username: 
set /p FMC_PASSWORD=API password: 
set /p INSECURE=Skip TLS verify? [y/N]: 

echo.
echo Installing Python dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo pip install failed.
    pause
    exit /b 1
)

set EXTRA=
if /I "%INSECURE%"=="y" set EXTRA=--insecure

echo.
python fmc_collect_data.py --host %FMC_HOST% --user %FMC_USER% --password %FMC_PASSWORD% %EXTRA% --output .
if errorlevel 1 (
    echo Collection failed.
    pause
    exit /b 1
)

for /f "delims=" %%D in ('dir /b /ad /o-d run-* 2^>nul') do (
    set LATEST=%%D
    goto :found
)
:found
if not defined LATEST (
    echo No run-* folder found.
    pause
    exit /b 1
)

echo.
python build_html.py --input %LATEST%
echo.
python package_run.py --input %LATEST% --format zip
echo.
echo Done.
echo   Folder: %LATEST%\html_view\index.html
echo   Archive: fmc_audit_*.zip in this directory — send the zip to NetConverter.
pause
