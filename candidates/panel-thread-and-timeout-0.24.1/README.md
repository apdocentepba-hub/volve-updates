# VOLVÉ 0.24.1 — reparación del panel que deja de responder

**Fecha:** 28/10/2026 (Argentina). **Estado:** beta Windows x64; compilación y tests locales aprobados; aún no validado en PC del usuario.

## Problema reproducido visualmente

El usuario abrió el panel 0.24.0 y Windows mostró `(No responde)` durante el mensaje “Leyendo políticas de Windows y el catálogo”. Había unas 160 reglas propias y más de 600.000 dominios informados por el catálogo, sin DNS masivo activo.

## Cambios concretos

- El hilo de la ventana Win32 ahora queda fijo a un hilo nativo con `runtime.LockOSThread` para mantener `GetMessageW` / `DispatchMessageW` en el mismo hilo que creó la ventana.
- Diagnóstico ejecutado desde un proceso hijo oculto `--panel-report`, aislado del bucle de mensajes, con límite real de 20 segundos mediante `exec.CommandContext`. Ante límite o error informa problema, no deja un panel bloqueado.
- `inspect` utiliza 1 lectura por clave de política (3 consultas agrupadas) en lugar de 160 procesos `reg.exe` individuales. Parser `parseRegStringValues` y pruebas de formato.
- Continúa limitando a una comprobación por vez y permite volver a consultar.
- Compatibilidad con `estado.json` de 0.24.0 y versiones previas.
- No activa motor DNS, no modifica configuraciones de adaptador, no toca tareas de terceros. Conserva el aviso sobre falta de bloqueo de red.

## Validación

`go test ./... -count=1` aprobado. `go test -race ./... -count=1` aprobado. `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...` aprobado. Cross-build Win64 GUI PE32+ aprobado. ZIP CRC y SHA256 revisados.

**SHA256 EXE:** `1f48503c5b0a8b6f139abe83f6bc2cca1b7caa95b7e5315d70083ea1f54cc205`

## Respaldos

- [Ejecutable en Google Drive](https://drive.google.com/file/d/1veRSMKCZEw29hES4QDBd3hpMU-i2pWMQ/view)
- [Código fuente + instalador ZIP](https://drive.google.com/file/d/1Jxl-sUMCQiO3-AcDA7XVvfGMrVcUENy3/view)

**Pendiente:** prueba manual en Windows para confirmar apertura, refresco y cierre; activation DNS masivo con recuperación ante fallos. No publicar en stable todavía.
