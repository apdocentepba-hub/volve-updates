# VOLVÉ 0.16.2 — Puente de actualizaciones integrales a Windows

**CANDIDATO SOLO FUENTES. NO INSTALAR EN WINDOWS NI PUBLICAR EN STABLE.**

## Completado en código
- Un solo lanzador estable (panel / motor con `--serve` / actualizador y diagnóstico de solo lectura).
- Auditoría de tareas `VOLVE-06-DNS`, `VOLVE-06-WATCHDOG` y `VOLVE-Actualizaciones`; inventario de adaptadores DNS y estados diferenciados `PARCIAL`, `NO_VERIFICABLE`, `DNS_LOCAL_CONFIGURADO`.
- Planificación de tareas con rutas permanentes `C:\Program Files\VOLVE\VOLVE.exe` y argumentos controlados.
- Prototipo no utilizado de registro nativo con cmdlets de Windows `New-ScheduledTaskAction`/`Register-ScheduledTask`, sin XML manual.
- Orquestador de rollback del motor simulado: cuando el nuevo motor falla después del cambio de versión, restaura el puntero, intenta reiniciar el motor anterior y lo vuelve a probar. Marca fallo CRITICAL si la restauración del motor falla.
- Se conservan HTTPS+Ed25519, validador ZIP integral, control de versiones y transacciones de 0.16.1.

## Evidencia
43/43 pruebas Go aprobadas, `go test -race` OK, `go vet` OK; compilación del lanzador Windows/amd64 y binario de pruebas de winsetup exitosa. **Sin pruebas de ejecución en Windows real.**

Respaldo privado del código en Google Drive:
`VOLVE_0162_PUENTE_WINDOWS_FUENTES_NO_INSTALAR.zip`
SHA256: `c20571bf0794b24638bc9fa5146b6c1ee3f6683586e5f9e6b8f27553e2825bf9`

## Bloqueos
Registro de tareas **no transaccional** todavía (no habilitar), integración real de motor/servicio DNS, catálogo real, firma Authenticode, instalador todo en uno, migración y pruebas Windows. No publicar el canal `stable` hasta validar en Windows limpio y existente. No prometer que bloquea todas las VPN.

Próximo bloque: implementar registro y rollback completo de tareas de Windows; integración de inventario de adaptadores con respaldo/restauración del DNS; empaquetado y validación de un solo instalador.
