@echo off
REM rqbit tunnel — Windows one-click client launcher.
REM Double-click this file, or run:  client-run.bat <server-host:port>
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0client-run.ps1" %*
echo.
echo Tunnel client stopped.
pause
