@echo off
setlocal
cd /d "%~dp0"
title GatewayManager - Inicializacao validada

set "PYTHON=python"
if exist ".venv\Scripts\python.exe" set "PYTHON=.venv\Scripts\python.exe"

"%PYTHON%" diagnosticar_ssl.py --todos --somente-cadastro
if errorlevel 1 (
    echo.
    echo ERRO: Corrija o gateways.json e/ou os caminhos de certificados antes de iniciar.
    pause
    exit /b 1
)

echo.
echo Cadastro estruturalmente valido. Iniciando bot...
"%PYTHON%" bot.py

echo.
echo Bot encerrado.
pause
