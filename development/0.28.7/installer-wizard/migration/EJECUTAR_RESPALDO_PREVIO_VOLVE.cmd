@echo off
setlocal
cd /d "%~dp0"
title VOLVE - PREPARAR RESPALDO PROTEGIDO (SIN LIMPIEZA)
echo.
echo VOLVE - Preparacion de respaldo local protegido
echo No desinstala ni detiene nada y no cambia DNS, HOSTS ni tareas.
echo.
echo ATENCION: requiere "Ejecutar como administrador".
echo Genera un respaldo privado en C:\ProgramData; NO compartas esa carpeta.
echo.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0Preparar_Respaldo_VOLVE_SoloLectura.ps1"
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" (
  echo PREPARACION FINALIZADA. No se limpiaron componentes ni se instalo VOLVE.
) else (
  echo PREPARACION DETENIDA. No borrar tareas ni ejecutar desinstaladores antiguos.
)
echo.
echo Compartime SOLO una foto o texto de las lineas BACKUP_OK y MANIFEST_SHA256.
echo No compartas archivos privados de ProgramData.
pause
exit /b %RC%
