# VOLVÉ 0.17.0 — puente experimental de control de motor Windows

**SOLO FUENTES. NO INSTALABLE. NO PUBLICAR STABLE.**

## Implementación

Se desarrolló el nuevo paquete `enginehealth` con consultas DNS UDP directamente a `127.0.0.1` y `::1`, exigencia de NXDOMAIN para `test.casino.bet.ar` (canary bloqueado), resolución válida de `example.org` y rechazo de respuestas con ID falso, proxy sin bloqueo, upstream caído o destino no-loopback. El comando interno `VOLVE.exe --preflight` ahora exige esta comprobación además de la identidad del PID.

El backend nuevo de Windows `winsetup.NativeEngineDriver` implementa **en el compilador** la interfaz `upgrade.EngineDriver`:

- Preflight no invasivo de tarea `VOLVE-06-DNS` (lanzador estable, SYSTEM, `--motor`, sin timeout), respaldo DNS, identidad exacta de ambos puertos UDP53 y filtro real.
- Rechaza si hay tarea heredada `VOLVE-06-WATCHDOG` **habilitada**, para impedir carreras con el supervisor antiguo.
- Rutina de reinicio *experimental* con verificación de proceso propietario de UDP53 y de su ruta bajo `Program Files\\VOLVE\\releases\\<versión>\\motor`; no mata procesos ajenos, ni altera DNS/adaptadores, ni crea tareas.
- **No está conectada al ejecutable de producción ni a un actualizador automático.** La rutina que mutaría procesos NO se ejecutó en Windows. Falta auditoría real de tarea/watchdog, reintentos, cortes y restauración.

## Validación (28/10/2026)

- `go test ./... -count=1`: OK
- `go test -race ./... -count=1`: OK
- `go vet ./...` (Linux y destino Windows64): OK
- Tests del motor legado: OK
- Cross-compilación lanzador y binario de pruebas de Windows64: OK, **sin ejecutarlo**.
- 153 funciones `Test*` definidas entre repositorios; las específicas Windows no pudieron ejecutarse aquí.
- ZIP de fuentes en Drive privado: `VOLVE_0170_CONTROL_MOTOR_WINDOWS_FUENTES_NO_INSTALAR.zip` (127747 bytes); SHA256 `7bc5e1bde20985c94a36b890a264ea12ceea15d24869252565a840bf6ec7c8f4`.

## Para terminar el instalador único

Migración transaccional del **watchdog heredado** con restauración segura; reemplazo completo del motor y panel + agente, permisos ACL, validación Authenticode y catálogo inicial real; pruebas de Windows reales de reinicio, fallo y rollback. Mantener `stable` sin versión hasta completar. Ninguna modificación en la PC del usuario.
