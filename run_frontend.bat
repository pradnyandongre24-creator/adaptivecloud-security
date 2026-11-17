@echo off
TITLE AdaptiveCloud Frontend Dashboard
cd /d "%~dp0frontend"
echo ======================================================================
echo          STARTING ADAPTIVE CLOUD FRONTEND DASHBOARD
echo ======================================================================
echo Dashboard URL: http://localhost:5173
echo.
call npm.cmd run dev
pause
