@echo off
rem securechat client — run from any folder.
rem Usage: run_client.bat [--host IP] [--port 8400] [--tor] [--tls] [...]
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 "%~dp0client.py" %*
) else (
    python "%~dp0client.py" %*
)
