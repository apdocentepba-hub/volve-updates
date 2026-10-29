# VOLVÉ 0.28.7 — Ensayo de reinicio REAL en una VM (NO INSTALAR EN TU PC)

**Estado:** protocolo de laboratorio. No es un instalador, no actualiza el motor DNS y no debe ejecutarse en la computadora donde está instalado VOLVÉ 0.28.6.

## Objetivo

Demostrar que una tarea `SYSTEM` con disparador `AtStartup`, registrada antes de un apagado de Windows, puede recuperar el estado de **una tarea de prueba inocua** desde un respaldo verificado **después de un reinicio real**. Hasta ahora GitHub Actions sólo ha activado manualmente ese disparador sin reiniciar la máquina.

## Prerequisitos

- VM **dedicada**, descartable, con Windows 10/11 de prueba, PowerShell elevado y checkpoint/snapshot previo.
- Archivo `vm_reboot_proof.ps1` de este directorio.
- Archivo `boot_recovery_lab.ps1` de este directorio, y `volve-journal-lab.exe` compilado en la **VM de pruebas** desde `build/codigo/cmd/volve-journal-lab` de las fuentes 0.28.7. **No distribuir esos binarios ni instalarlos en la PC del usuario.**
- La VM no debe ser un equipo de trabajo ni contener datos importantes. El script identifica el hipervisor y **rechaza equipos físicos**; no inicia el reinicio automáticamente.

## Procedimiento para un operador de laboratorio

1. Ejecutar PowerShell elevado **dentro de la VM**, crear un snapshot de la VM y comprobar los prerrequisitos:
   ```powershell
   .\vm_reboot_proof.ps1 -Mode Probe
   ```
2. Preparar el ensayo (reemplazar los dos paths con rutas absolutas dentro de la VM):
   ```powershell
   .\vm_reboot_proof.ps1 -Mode Prepare -LabScript C:\Lab\boot_recovery_lab.ps1 -JournalExe C:\Lab\volve-journal-lab.exe
   ```
   Anotar el `RunId` numérico que imprime. El script crea **exclusivamente tareas de prueba** `VOLVE-CI-StartupMotor-<RunId>` y `VOLVE-CI-BootRecovery-<RunId>`. Los archivos quedan en `C:\ProgramData\VOLVE-VM-RebootLab-<RunId>`, protegidos para Administradores y SYSTEM.
3. **Reiniciar manualmente únicamente la VM dedicada**, desde su propia consola o la plataforma de virtualización. No reiniciar ninguna PC de usuario ni un runner público de CI.
4. Tras iniciar Windows, volver a abrir PowerShell elevado dentro de la misma VM:
   ```powershell
   .\vm_reboot_proof.ps1 -Mode Verify -RunId <RunId>
   ```
   La verificación exige nuevo tiempo de arranque, ejecución exitosa de la tarea `SYSTEM` tras ese arranque, estado `restored` del journal y restauración exacta de `cmd.exe /C exit 0`.
5. Conservar la evidencia y retirar exclusivamente las tareas de prueba:
   ```powershell
   .\vm_reboot_proof.ps1 -Mode Cleanup -RunId <RunId>
   ```

## Límites, antes de producción

- Pasar este protocolo en una VM con reinicio real **no demostraría todavía la recuperación del DNS real**. Para ello hará falta integrar un controlador de actualización del motor, con permisos verificados, copias versionadas, motor DNS de prueba en el puerto 53 dentro de un laboratorio y restauración comprobada de IPv4/IPv6.
- Si la VM falla en volver a iniciar, restaurar su snapshot; nunca hacer el ensayo sobre la computadora personal.
- Las comprobaciones de GitHub Actions para este script sólo prueban **sintaxis y guardas de laboratorio**; no se consideran un reinicio real.
