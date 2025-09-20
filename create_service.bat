@echo off
echo Instalando servicio VPEW-AI...

REM Verificar permisos de administrador
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: Se requieren permisos de administrador
    echo Ejecuta este archivo como administrador
    pause
    exit /b 1
)

REM Crear servicio usando sc create
sc create VPEWAgent binPath= "C:\ProgramData\vpew-ai\venv\Scripts\python.exe -c \"import time; print('VPEW-AI Service Running'); [time.sleep(60) for _ in iter(int, 1)]\"" DisplayName= "VPEW-AI Security Agent" start= auto

if %errorLevel% equ 0 (
    echo Servicio creado exitosamente
    
    REM Iniciar el servicio
    sc start VPEWAgent
    
    if %errorLevel% equ 0 (
        echo Servicio iniciado exitosamente
        sc query VPEWAgent
    ) else (
        echo Error iniciando el servicio
    )
) else (
    echo Error creando el servicio
)

pause
