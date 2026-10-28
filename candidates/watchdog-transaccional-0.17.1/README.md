# VOLVÉ 0.17.1 — watchdog transaccional (solo fuentes)

**NO INSTALAR. NO HABILITAR `stable`.** 28/10/2026.

## Implementado

- Pausa transaccional del watchdog heredado `VOLVE-06-WATCHDOG`: inspección y validación de acción reconocida, respaldo completo XML+estado antes de cualquier cambio, verificación de tarea desactivada y proceso detenido.
- Registro de recuperación en disco con escritura atómica, rechazo de sobrescritura y control básico de corrupción. Si falla el respaldo, no desactiva el watchdog; si la restauración falla, mantiene el registro y devuelve un error crítico.
- `winsetup.NativeWatchdogController` experimental para Windows: exporta, deshabilita, detiene y restaura la tarea; rechaza intérpretes de scripts, ejecutables relativos, tareas no reconocidas o principal no SYSTEM. No cambia DNS de adaptadores.
- `winsetup.UpgradeExistingWithWatchdog`: el motor nuevo debe comprobarse junto al supervisor de reemplazo. Ante fallo, solo restaura el watchdog cuando se verifican tanto la versión anterior activa como el motor DNS anterior. Si el estado es incierto, el registro persiste y no se reanima el watchdog por suposición.

## Validación

- 170 funciones `Test*` definidas en ambos módulos: 149 del proyecto principal y 21 del motor legado.
- `go test ./... -count=1`, `go test -race ./... -count=1`, `go vet ./...` (proyecto principal): aprobados en Linux.
- Pruebas del motor legado: aprobadas en Linux.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: aprobado.
- Compilación cruzada de `cmd/volve-bootstrap` y `go test -c ./winsetup` para Windows AMD64: correcta **sin ejecutar en Windows**. El empaquetador `cmd/volve-releasebuild` es deliberadamente solo de desarrollo Linux/no-Windows.

## Respaldo privado

Google Drive, carpeta **VOLVE - Actualizaciones**:
`VOLVE_0171_WATCHDOG_TRANSACCIONAL_FUENTES_NO_INSTALAR.zip`

SHA-256: `b9017449160c6f213bf9bb75560cb272d8ae526bbce98324896da47afce3570c` (139757 bytes). Informe PDF separado en la misma carpeta.

## Pendiente antes de producción

1. Auditoría y pruebas reales de Task Scheduler y controlador DNS en Windows, especialmente reinicio, corte, recuperación y versión previa.
2. Supervisor nuevo verificable, exclusión global de procesos de instalación y ACL protegidas de la carpeta de respaldo.
3. Migración segura si el watchdog legado usa PowerShell; actualmente se **rechaza** en preflight.
4. Integración efectiva de panel, motor, agente y actualizador; firma Authenticode y catálogo completo; validación anti-evasión VPN sin promesas de bloqueo perfecto.

**La instalación del usuario no se modificó.** No hay release estable ni `VOLVE_Setup.exe` instalable en esta versión.