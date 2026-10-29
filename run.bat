@echo off
setlocal
where py >nul 2>nul
if not errorlevel 1 (
    py -3 "%~dp0mini_packet_analyzer.py" %*
    exit /b
)
python --version >nul 2>nul
if not errorlevel 1 (
    python "%~dp0mini_packet_analyzer.py" %*
    exit /b
)
if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" (
    "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" "%~dp0mini_packet_analyzer.py" %*
    exit /b
)
echo Python 3.9 or newer is required. Install Python and try again.
exit /b 1
