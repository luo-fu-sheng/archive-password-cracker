@echo off
chcp 65001 >nul
set "APP_DIR=%~dp0"
cd /d "%TEMP%"
where pythonw >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw "%APP_DIR%app.py"
) else (
    python "%APP_DIR%app.py"
)
