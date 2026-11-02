# VOLVÉ 0.28.7 — Candidato DNS real, falla controlada y recuperación del motor anterior

**SOLO PARA VM DESCARTABLE. NO ES INSTALADOR NI ACTUALIZACIÓN DE VOLVÉ 0.28.6.**
Este laboratorio requiere un snapshot de Hyper-V, ejecutables diferenciados compilados en Windows CI y un directorio de laboratorio nuevo. No altera DNS configurado en adaptadores, navegador, hosts ni tareas productivas.

A diferencia del ensayo anterior (`cmd.exe /C exit 83`), aquí el **candidato de motor es un EXE Go completo** (`VOLVE_CI_Failing_Candidate.exe`) con el mismo servicio DNS principal. Lo ejecuta SYSTEM una sola vez antes de reiniciar, verifica sus seis respuestas IPv4/IPv6, escribe prueba SHA-256 y **sale con 83**. Se evita una carrera al reiniciar: la tarea candidata usa un disparador de fecha futura (no AtStartup), mientras el watchdog SYSTEM tiene AtStartup. Tras reiniciar, el watchdog debe restaurar el XML original sellado, arrancar motor Full CI original y probar 6/6 DNS antes de firmar un recibo de recuperación **de laboratorio**. No hay firma editorial de producto.

## Antes de ejecutar
- VM `VOLVE-LAB-0287` desconectada de la PC productiva; crear/verificar checkpoint `ANTES-CANDIDATO-REAL-0287`.
- Descargar artefacto del workflow `volve-0287-vm-real-candidate-rollback.yml` **solo si GitHub Actions finaliza SUCCESS**. Extraerlo íntegro en `C:\Lab\CandidateRollback`, sin sobrescribir archivos de kits anteriores.
- Proponer LabId `20261102000401`, **solo si no existe** la carpeta `C:\ProgramData\VOLVE-CI-FreshDNS53-20261102000401`; si existe detenerse, no borrar ni reutilizar.
- Ejecutar Windows PowerShell como Administrador **en la VM**, habilitar TaskScheduler Operational.

## Preparar y comprobar el fallo real

```powershell
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\CandidateRollback\vm_full_motor_reboot_dns.ps1" -Mode Probe
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\CandidateRollback\vm_real_candidate_dns_rollback.ps1" -Mode Probe

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\CandidateRollback\vm_full_motor_reboot_dns.ps1" -Mode Prepare -LabId 20261102000401 -MotorExe "C:\Lab\CandidateRollback\VOLVE_CI_FreshDNS53.exe"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\CandidateRollback\vm_real_candidate_dns_rollback.ps1" -Mode Arm -LabId 20261102000401 -SourceCandidate "C:\Lab\CandidateRollback\VOLVE_CI_Failing_Candidate.exe"
```

La preparación **solo se aprueba con mensaje ARMED** que declare el candidato real 6/6, SYSTEM, exit83 y watchdog armado. Si falla: NO reiniciar, NO repetir el LabId, NO borrar archivos ni tareas; aportar salida para plan de recuperación. La tarea original se conserva como XML protegido.

## Reinicio real y prueba independiente
**Solo después de ARMED**, reiniciar manualmente Windows **dentro de la VM**. En una ventana PowerShell de Administrador ejecutar:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\CandidateRollback\vm_real_candidate_dns_rollback.ps1" -Mode Verify -LabId 20261102000401
```

El éxito deberá declarar `PASS: real Windows VM reboot; distinct real Full CI candidate exited83...` y guardar `C:\ProgramData\VOLVE-CI-FreshDNS53-20261102000401\real-candidate-rollback-proof.json`. Adjuntar JSON antes de limpiar.

**Solo después de auditar el JSON**, dentro de la VM:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\CandidateRollback\vm_real_candidate_dns_rollback.ps1" -Mode Cleanup -LabId 20261102000401
```

Cleanup solo retira las dos tareas temporales, conserva evidencia y no modifica DNS de Windows. No restaurar checkpoints ni apagar ante un error de Verify hasta preservar la evidencia.

## Límites

No se ha probado todavía esta secuencia con reinicio real de VM; la corrida CI solo preparará el estado sin reiniciar. La firma editorial auténtica del motor productivo, permiso de migración desde el EXE antiguo, reemplazo real de bytes/tarea y el soporte del Centro de producción continúan PENDIENTES. La aceptación técnica del actualizador de producción se mantiene 65/100.
