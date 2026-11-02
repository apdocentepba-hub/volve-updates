# VOLVÉ 0.28.7 — reinicio real, fallo de candidato DNS y rescate SYSTEM

Fecha: 2026-11-02 (Argentina). VM aislada, LabId `20261102000401`.

## REALIZADO / DECLARADO POR EL OPERADOR
- Se ejecutó `vm_full_motor_reboot_dns.ps1 -Mode Prepare` con catálogo Full DNS de **400005 líneas**.
- Se ejecutó `vm_real_candidate_dns_rollback.ps1 -Mode Arm`: el **candidato DNS real de CI** atendió 6/6 consultas IPv4/IPv6 como SYSTEM, terminó intencionalmente con código 83 y dejó armado el recuperador.
- Tras reiniciar realmente Windows invitado se ejecutó `vm_real_candidate_dns_rollback.ps1 -Mode Verify -LabId 20261102000401`.
- Salida literal provista por el operador: `PASS: real Windows VM reboot; distinct real Full CI candidate exited83, SYSTEM restored original Full DNS motor, IPv4+IPv6 6/6 and TCP Internet. Evidence: C:\ProgramData\VOLVE-CI-FreshDNS53-20261102000401\real-candidate-rollback-proof.json`.
- La herramienta advierte `NOT a production signed 0.28.6 -> 0.28.7 migration.`

## ESTADO DE COMPROBACIÓN
**PASS textual en la VM:** el verificador afirma recuperación autónoma del motor Full DNS original tras reinicio real del mismo Windows, eventos de tarea SYSTEM, DNS dual-stack 6/6, Internet TCP. Esta prueba posterior al reinicio cierra el escenario de **fallo de candidato DNS real de laboratorio**, distinto del ensayo anterior con `cmd.exe`.

**Todavía pendiente:** recibir el contenido del `real-candidate-rollback-proof.json` para auditar GUID de la instancia, IDs y registros de Task Scheduler, hashes de original/candidato y constancia de recibos. `Cleanup` todavía NO confirmado; conservar VM/plan/tareas y no borrar evidencia.

## LÍMITES
El candidato era binario exclusivo de CI con fallo intencional, no un motor productivo firmado. El motor de rollback era Full CI de laboratorio, no el 0.28.6 del equipo principal. NO publicar canal ni tocar el host. Puntuación formal de aceptación productiva sigue 65/100 hasta aprobar transacción firmada real y validación de instalación.

## SIGUIENTE PASO
1. Auditoría del archivo `real-candidate-rollback-proof.json`.
2. Una vez auditado, limpieza controlada `-Mode Cleanup -LabId 20261102000401` dentro de la VM y constancia `CLEAN`.
3. Pruebas pendientes de migración productiva firmada y compatibilidad del Centro.

## CIERRE CONFIRMADO POR OPERADOR
El operador adjuntó y se revisó `real-candidate-rollback-proof.json` del LabId `20261102000401`: reinicio VM real, instancia de watchdog correlacionada con eventos 118/100/201/102, estado 0, motor original y candidato con SHA-256 diferentes, DNS IPv4/IPv6 6/6 y TCP Internet. No se recalcularon hashes sobre binarios.

También ejecutó `-Mode Cleanup -LabId 20261102000401` dentro de la VM. Salida reportada: `CLEAN: two disposable real-candidate VM tasks removed; all protected evidence retained.` Por tanto el ensayo de laboratorio de candidato DNS real y rollback SYSTEM queda **CERRADO**, sin tareas temporales. La instalación física Windows 0.28.6 no fue modificada por estas pruebas.

**Límite:** sigue pendiente migración productiva firmada de 0.28.6 a 0.28.7, con instalación y recuperación de un verdadero motor publicado. Indicador formal 65/100.
