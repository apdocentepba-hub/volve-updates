@echo off
cd /d "%~dp0"
echo VOLVE 0.28.7 - Verificacion de propietario DNS53 - SOLO LECTURA.
echo Ejecutar este archivo COMO ADMINISTRADOR.
echo.
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0Ejecutar_Proceso_DNS53_Reporte.ps1"
if errorlevel 1 (
  echo ERROR: no se pudo completar el informe. Envia una captura.
) else (
  echo Adjunta al chat el nuevo archivo VOLVE_PC_PROCESO_DNS53_SOLO_LECTURA_*.json.
)
pause
