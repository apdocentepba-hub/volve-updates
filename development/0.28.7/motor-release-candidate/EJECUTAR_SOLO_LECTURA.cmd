@echo off
cd /d "%~dp0"
echo VOLVE 0.28.7 - SOLO LECTURA - no instala ni modifica el motor o DNS.
echo Es necesario usar clic derecho ^> Ejecutar como administrador.
echo.
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0Ejecutar_y_Guardar_Reporte.ps1"
if errorlevel 1 (
  echo.
  echo No se pudo generar el informe. Envia una captura del error.
) else (
  echo.
  echo Informe generado. Adjunta el JSON al chat.
)
echo.
pause
