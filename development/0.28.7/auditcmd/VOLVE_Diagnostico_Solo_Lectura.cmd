@echo off
setlocal
set "VOLVE_AUDIT_EXE=%~dp0VOLVE_Diagnostico_0_28_7_Solo_Lectura.exe"
if not exist "%VOLVE_AUDIT_EXE%" (
 echo No se encontro el diagnostico de VOLVE junto a este archivo.
 pause
 exit /b 2
)
echo VOLVE 0.28.7 - DIAGNOSTICO SOLAMENTE. NO INSTALA NI MODIFICA DNS.
echo Windows solicitara permiso de administrador para leer tareas y adaptadores.
powershell.exe -NoProfile -NonInteractive -Command "Start-Process -FilePath $env:VOLVE_AUDIT_EXE -Verb RunAs -Wait"
if errorlevel 1 (
 echo Diagnostico cancelado o no disponible. No se cambio el sistema.
 pause
 exit /b 1
)
echo Busque VOLVE_Diagnostico_Solo_Lectura_*.json en la carpeta Descargas.
echo No se modificaron las tareas ni el DNS.
pause
