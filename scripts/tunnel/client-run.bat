@echo off
REM rqbit tunnel managed-client control wrapper.
REM Forward arguments to the PowerShell menu, then keep double-click windows open.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0client-run.ps1" %*
set "EXITCODE=%ERRORLEVEL%"
echo.
pause
exit /b %EXITCODE%
