@echo off
REM Black Glove - one-click web app launcher
cd /d "%~dp0.."
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Launch-BlackGlove-Web.ps1" %*
if errorlevel 1 (
    echo.
    echo Launch failed. See errors above.
    pause
)
