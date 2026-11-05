# VOLVÉ 0.28.7 — Candidato firmado de laboratorio + DNS/53 Full + watchdog SYSTEM independiente

Fecha: 03/11/2026 (Argentina). Rama: `fix/0287-signed-lease-guard`; PR #3 **DRAFT**. No instalar, no publicar, no modificar un motor productivo.

## HITO NUEVO — COMPROBADO EN WINDOWS

- **PASS**: [GitHub Actions #41624339283](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41624339283), trabajo `fresh-system-dns53`, sobre commit `d12969a6ed03fc5464dbc8889ff860ba5eb0d259`.
- El nuevo test obligatorio `TestSignedFullDNS53SYSTEMTaskAndIndependentRollback` está implementado en `development/0.28.7/inapp/volveci_signed_full_dns53_system_windows_test.go`, se reconstruye vía la allowlist de `apply_overlay.go`, y se ejecuta con tag `volveci` en la VM Windows alojada y descartable. El workflow impide aprobar una prueba omitida, exige sus dos hitos de log y verifica el resultado por `go test -json`.
- Antes de cambiar una tarea, observa ausencia de tareas productivas, comprueba la VM alojada, ausencia de listeners preexistentes TCP/UDP 53 y hace snapshot de DNS de adaptadores y SHA-256 de `hosts`.
- El motor verdadero compilado desde el código Go de VOLVÉ se copia como candidato **firmado Ed25519 con clave temporal de CI**; verifica manifest, tamaño y SHA-256 antes y después de su instalación temporal.
- Crea únicamente `VOLVE-CI-ManagedMotor-*` y `VOLVE-CI-ManagedWatchdog-*`, respalda la tarea original y arma el watchdog SYSTEM independiente antes de la conmutación.
- La tarea SYSTEM cambia al EXE firmado en modo `--ci-fresh-dns53` con token de VM, arranca el motor Full desde ProgramData de laboratorio (400.005 dominios/reglas) y responde DNS real UDP/53 en `127.0.0.1` y `::1`. Verifica dominios de apuestas bloqueados con NXDOMAIN y `example.org` permitido, sin cambiar DNS configurados de Windows.
- Comprueba la identidad del proceso SYSTEM que tiene posesión EXCLUSIVA de UDP/53 en ambas familias, no solo la respuesta DNS de cualquier proceso.
- Detiene el motor candidato, ejecuta el watchdog independiente bajo SYSTEM, exige journal de recuperación y tarea original `cmd.exe /C exit 0` con XML SHA-256 inalterado. Firma del candidato permanece verificable.
- Los DNS de adaptadores y el archivo `hosts` deben seguir idénticos al snapshot previo.

## DEFECTO DETECTADO Y CORREGIDO

- Primera ejecución [#41623901237](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41623901237): **FAIL** ANTES de cambiar tareas, porque el PowerShell hijo del proceso Go no tenía `Get-FileHash` disponible. No fue un fallo del motor, de la recuperación o de la firma.
- Corrección: usar `System.Security.Cryptography.SHA256` directamente desde .NET, lectura con `File.OpenRead` y cierre explícito de recursos. Reejecución **SUCCESS** #41624339283.

## OTROS CONTROLES DE LA MISMA REVISIÓN

- Centro+Updater [#41624339278](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41624339278): **SUCCESS**.
- Centro 0.28.7 publicado, prueba DNS bajo SYSTEM y watchdog separado [#41624339254](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41624339254): **SUCCESS**.
- Migración firmada sintética + watchdog [#41624339555](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41624339555): en ejecución al registrar este archivo.
- Regresión completa `motorupdate` + watchdog, 13 jobs [#41624339242](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41624339242): en ejecución al registrar este archivo. No declarar verde hasta finalizar.

## PROHIBICIONES Y SIGUIENTE PUERTA

Esta prueba **NO** utiliza la clave privada auténtica del editor, **NO** obtiene un permiso editorial de migración genuino, **NO** reemplaza `VOLVE-DNS-SERVER-0270`, **NO** migra un 0.28.6 instalado y **NO** reinicia un Windows persistente después de una transacción productiva. Tampoco crea un instalador final. El Centro 0.28.7 distribuido en `main` es distinto de una release productiva del motor 0.28.7.

**Aceptación técnica del actualizador: 65/100.** PR DRAFT sin fusionar, release de motor bloqueada y PC del usuario intacta.

**¿Hace falta la VM persistente del usuario ahora? NO.** El LabId `20261102000401` ya fue auditado y limpiado después de probar rollback de un candidato Full CI distinto; no repetirlo ni reutilizarlo. La próxima sesión en esa VM deberá usar un paquete nuevo, SHA-256 conocido, checkpoint previo, permiso editorial auténtico, candidato DNS firmado como producto y controlador de migración productiva para reproducir una actualización de 0.28.6 con fallo e intento de recuperación tras reinicio completo. Hasta que esos elementos existan, no hay ensayo adicional en la VM que acredite el criterio pendiente.
