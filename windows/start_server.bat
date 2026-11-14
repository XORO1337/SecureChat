@echo off
rem securechat relay server — run from this folder.
rem Usage: run_server.bat [--host 0.0.0.0] [--port 8400] [--tls] [...]
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 "%~dp0server.py" %*
) else (
    python "%~dp0server.py" %*
)
        