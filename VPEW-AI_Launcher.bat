@echo off
title VPEW-AI Launcher
color 0A

echo.
echo  ====================================================
echo   VPEW-AI - Vigilancia Proactiva para Endpoints
echo   Launcher de Interfaz Grafica
echo  ====================================================
echo.

cd /d "%~dp0"

echo [INFO] Verificando sistema...

REM Verificar si Python esta disponible
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python no encontrado
    echo [INFO] Instale Python 3.10+ para continuar
    pause
    exit /b 1
)

REM Verificar si el virtualenv existe
if not exist "C:\ProgramData\vpew-ai\venv\Scripts\python.exe" (
    echo [WARNING] Virtualenv no encontrado
    echo [INFO] Ejecutando instalacion...
    python install_vpew.py
)

echo [INFO] Iniciando VPEW-AI GUI...
echo [INFO] Presione Ctrl+C para cerrar

REM Ejecutar VPEW-AI Main
python vpew_main.py

echo.
echo [INFO] VPEW-AI GUI cerrado
pause
