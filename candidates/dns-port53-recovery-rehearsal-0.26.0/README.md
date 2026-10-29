# VOLVÉ 0.26.0 — ensayo de DNS 53 y reversión transaccional

**Estado:** beta experimental, 29/10/2026 (hora Argentina). El DNS del adaptador de Windows **NO** se modifica.

## Código integrado
- Se portó del código previo de VOLVÉ el paquete `dnsactivation` (journal duradero, validación de snapshots, bloqueo de activaciones simultáneas, `Activate`, `Recover`, `Monitor` y pruebas de fallos).
- Se incorporó `dnsrollout`: inventario DNS **solo lectura** con PowerShell (GUID, índice, modo y resolutores), rechazo de inventarios ambiguos, y simulación con fallo provocado después de cambiar un **adaptador simulado**. Comprueba compensación y limpieza del diario temporal.
- El motor DNS real con el catálogo completo de HaGeZi se inicia temporalmente en **127.0.0.1:53**, bloquea una consulta del feed, responde una consulta permitida mediante un upstream de prueba local y verifica TCP.
- Cierra los listeners y comprueba que el puerto 53 pueda ocuparse de nuevo. La prueba IPv6 en ::1 es opcional y se informa.
- El panel Win32 heredado de 0.25.0 incluye el botón **«Ensayar activación / rescate (sin cambiar DNS)»**, aislado en un proceso con límite de 100 segundos.
- Sin cambios al Registro, `hosts`, tareas ni adaptadores durante esta prueba; la instalación existente 0.25.0 sigue intacta si se abre solo el panel.

## Pruebas ejecutadas en Linux
- `go test ./... -count=1`: OK.
- `go test -race ./... -count=1`: OK.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: OK.
- Build PE32+ Windows x64 GUI: OK.
- ZIP CRC + igualdad byte por byte del EXE: OK.
- SHA-256 EXE: `acaf50ff050c00930344cd1f5662de0e18a1a62b4b1b52023a0792717da7730e`.

## Entregables
- [VOLVE 0.26.0 ejecutable en Google Drive](https://drive.google.com/file/d/1h75lI-IJeGoG4RKjG5daUKi2bTNH0Lgh/view)
- [Fuente Go, pruebas y ejecutable en ZIP](https://drive.google.com/file/d/1CcjVS00cgSvGcne37tYHdfouGxSmmQVb/view)

## Criterios NO cumplidos todavía
- No se comprobó la ejecución en Windows real de esta revisión ni un cambio reversible del DNS del adaptador.
- No se registró ni validó watchdog SYSTEM independiente ni restore real después de reinicio/corte.
- El motor DNS no queda residente, ni cambia el resolvedor de Windows.
- La versión NO debe anunciarse como protección DNS sistémica operativa; no activar canal `stable` antes de validar todo el recorrido real en VM Windows con rollback y reconexión.
