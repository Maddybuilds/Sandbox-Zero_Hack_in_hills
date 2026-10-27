@echo off
setlocal
cd /d "%~dp0"
title Sandbox Zero - Judge quickstart
if exist ".judge-venv\Scripts\python.exe" (
  ".judge-venv\Scripts\python.exe" -c "import sys; raise SystemExit(sys.version_info < (3, 11))" >nul 2>&1
  if not errorlevel 1 goto use_venv
)
py -3 -c "import sys; raise SystemExit(sys.version_info < (3, 11))" >nul 2>&1
if not errorlevel 1 goto use_py
python -c "import sys; raise SystemExit(sys.version_info < (3, 11))" >nul 2>&1
if not errorlevel 1 goto use_python
python3 -c "import sys; raise SystemExit(sys.version_info < (3, 11))" >nul 2>&1
if not errorlevel 1 goto use_python3
echo.
echo Python 3.11 or newer is needed for this local demo.
echo Install Python from https://www.python.org/downloads/ and enable its PATH option.
echo Then double-click START_JUDGES.cmd again. No Linux or Docker is required.
echo.
pause
exit /b 1
:use_venv
".judge-venv\Scripts\python.exe" -u judge_start.py %*
goto finished
:use_py
py -3 -u judge_start.py %*
goto finished
:use_python
python -u judge_start.py %*
goto finished
:use_python3
python3 -u judge_start.py %*
:finished
set "SZ_JUDGE_EXIT=%errorlevel%"
if not "%SZ_JUDGE_EXIT%"=="0" pause
exit /b %SZ_JUDGE_EXIT%
