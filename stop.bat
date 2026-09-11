@echo off
title My Ida - Stop Host
cd /d "%~dp0"

echo Stopping anything on port 3000...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :3000 ^| findstr LISTENING') do (
  echo Killing PID %%a
  taskkill /F /PID %%a >nul 2>nul
)

echo Done. Server stopped.
timeout /t 2 /nobreak >nul
