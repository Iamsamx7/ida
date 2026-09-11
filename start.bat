@echo off
title My Ida - Start Host
cd /d "%~dp0"

echo Checking Node...
where node >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Node.js not found. Install it from https://nodejs.org/
  pause
  exit /b 1
)

if not exist "node_modules" (
  echo Installing dependencies first time...
  npm install
)

if not exist ".env" (
  if exist ".env.example" (
    echo Creating .env from .env.example...
    copy ".env.example" ".env" >nul
  )
)

echo.
echo Starting server at http://localhost:3000 ...
echo Opening browser...

rem Open browser after short delay so Next.js has time to boot
start "" cmd /c "timeout /t 3 /nobreak >nul & start \"\" http://localhost:3000"

npm run dev

pause
