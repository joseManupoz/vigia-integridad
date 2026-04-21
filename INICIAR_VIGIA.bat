@echo off
title Vigia de Integridad v4.0 - Urubamba
color 17
cls

echo.
echo  ==========================================================
echo   VIGIA DE INTEGRIDAD v4.0 - Sub-Prefectura Urubamba
echo   Jose Manuel Pozo Carlos - Sub-prefecto
echo  ==========================================================
echo.

:: Ir a la carpeta del programa
cd /d "%~dp0"

:: Verificar Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Python no instalado. Descargando e instalando...
    echo      Esto ocurre solo la primera vez.
    echo.
    powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe' -OutFile '%TEMP%\python_inst.exe'}"
    %TEMP%\python_inst.exe /quiet InstallAllUsers=0 PrependPath=1 Include_test=0
    echo  [OK] Python instalado. Reiniciando el sistema...
    timeout /t 3 >nul
    start "" "%~f0"
    exit
)

echo  [OK] Python instalado
echo.
echo  Iniciando Vigia de Integridad v4.0...
echo  El navegador se abre automaticamente.
echo.
echo  Direcciones disponibles:
echo    Principal: http://localhost:8080
echo    Ciudadano: http://localhost:8080/publico
echo.
echo  IMPORTANTE: No cierres esta ventana mientras uses el sistema.
echo  Para cerrar el sistema: presiona Ctrl+C aqui.
echo  ==========================================================
echo.

python servidor.py

echo.
echo  Sistema detenido. Tus datos estan guardados en vigia.db
pause
