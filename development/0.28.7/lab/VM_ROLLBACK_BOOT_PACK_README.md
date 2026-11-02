# VOLVÉ 0.28.7 — ensayo de recuperación SYSTEM tras reinicio real de una VM
**Edición:** 2026-11-02. **Exclusivamente VM descartable Windows con checkpoint previo. NO ejecutar en la PC anfitriona con 0.28.6.**

Este paquete NO instala ni actualiza el motor real. Simula una interrupción en la actualización de una **tarea inocua**, dejando un journal pendiente y una tarea **SYSTEM al inicio** que la restaura desde un respaldo XML comprobado y un binario anterior simulado. El verificador exige un reinicio de Windows genuino y eventos 118, 100, 201, 102 de **la misma instancia** del recuperador, además de journal cerrado correctamente. El helper Go `volve-journal-lab.exe` proviene de reconstrucción del código del piloto; no es un binario productivo firmado.

## Requisitos

1. Terminar el ensayo anterior del motor Full DNS53 y ejecutar su `Cleanup` con resultado `LIMPIEZA OK`.
2. Apagar la VM `VOLVE-LAB-0287` y crear en Hyper-V un punto de control llamado `ANTES-PRUEBA-ROLLBACK-0287`. Volver a encender la VM para la nueva prueba.
3. Descargar **únicamente dentro de la VM** el artifact del workflow `VOLVE-0287-VM-RECOVERY-BOOT-LAB-NO-INSTALL`, extraer completo en `C:\Lab\Rollback`. Conservar el manifiesto de hashes.
4. Ejecutar en PowerShell **administrador dentro de la VM**:
   ```powershell
   wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\Rollback\vm_reboot_proof.ps1" -Mode Probe
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\Rollback\vm_reboot_proof.ps1" -Mode Prepare -RunId 20261102000201 -LabScript "C:\Lab\Rollback\boot_recovery_lab.ps1" -JournalExe "C:\Lab\Rollback\volve-journal-lab.exe"
   ```
5. **Solo** si aparece `PREPARED` y verificación previa satisfactoria, reiniciar **el Windows de la VM** manualmente; no reiniciar el anfitrión. Después:
   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\Rollback\vm_reboot_proof.ps1" -Mode Verify -RunId 20261102000201
   ```
6. En caso de éxito debe existir `C:\ProgramData\VOLVE-VM-RebootLab-20261102000201\vm-proof-evidence.json`; enviar ese archivo para auditoría. Si falla, **no limpiar**; conservar journal y eventos.
7. Solo tras aprobación, retirar las dos tareas descartables con:
   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\Rollback\vm_reboot_proof.ps1" -Mode Cleanup -RunId 20261102000201
   ```

**Alcance limitado**: restaura una **tarea ficticia y journal** después de reinicio real, no el EXE DNS anterior ni una actualización de 0.28.6 a 0.28.7, y no valida la firma editorial productiva. Es un hito intermedio, no la liberación del actualizador. El punto de control evita arriesgar el sistema principal, pero no debe restaurarse antes de preservar evidencias.
