@echo off
cd /d "%~dp0"
echo VOLVE - Prueba funcional DNS IPv4 / IPv6 SOLO LECTURA.
echo Envia hasta seis consultas UDP53 locales; las consultas permitidas pueden reenviarse.
echo Ejecutar como ADMINISTRADOR. No instala ni detiene nada.
echo.
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0Ejecutar_DNS_Local_Reporte.ps1"
if errorlevel 1 (
 echo ERROR al producir informe. Envia captura del error.
) else (
 echo Adjunta al chat el archivo VOLVE_PC_DNS_LOCAL_SOLO_LECTURA_*.json.
)
pause
