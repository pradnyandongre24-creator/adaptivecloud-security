@echo off
TITLE AdaptiveCloud Full Stack Launcher
cls
echo ======================================================================
echo              ADAPTIVE CLOUD FULL-STACK LAUNCHER
echo ======================================================================
echo.
echo [1/2] Starting Backend Telemetry Hub (Port 8001)...
start "AdaptiveCloud Backend" cmd /k "cd /d %~dp0 && python agent\simulate_all_laptops.py"

echo [2/2] Starting Frontend Web Interface (Port 5173)...
start "AdaptiveCloud Frontend" cmd /k "cd /d %~dp0\frontend && npm.cmd run dev"

echo.
echo ======================================================================
echo   AdaptiveCloud is launching!
echo.
echo   * Web Dashboard:  http://localhost:5173
echo   * Backend Hub:    http://localhost:8001
echo   * Default Login:  admin / password123
echo ======================================================================
echo.
pause
