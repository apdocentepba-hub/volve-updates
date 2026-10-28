# VOLVÉ 0.22.0 — bloqueo ampliado de DNS-over-HTTPS (28/10/2026)

**Beta para Windows x64. No distribuir como versión estable validada.**

- Instalador único creado desde el código de la versión 0.21.0, sin cambiar la configuración DNS del adaptador.
- Se agregaron cuatro políticas: `DnsOverHttpsMode=off` para Chrome y Edge; `DNSOverHTTPS.Enabled=0` y `Locked=1` para Firefox.
- Las políticas existentes de terceros no se sustituyen; se registran como omitidas y se informan en diagnóstico.
- Recibo transaccional para comprobar y eliminar únicamente entradas DoH propias durante mantenimiento administrativo.
- Migración desde las versiones 0.19.0, 0.20.0 y 0.21.0; restauración de hosts también en instalaciones 0.20/0.21.
- `--doctor` expone diagnóstico en ventana; se preservan `--inspect`, `--selftest` y `--uninstall` administrativo.
- Motor auxiliar masivo, HaGeZi Full/Medium y tarea horaria preservados de la 0.21.0.

## Evidencias

- `go test ./... -count=1`: OK (Linux).
- `go test -race ./... -count=1`: OK (Linux).
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: OK.
- Compilación Windows x64 PE32+ GUI: OK.
- ZIP comprobado y hash del ejecutable SHA-256: `501b72eba0621299b0a5977cc3872ce84a608abf50fe8276ea95150defcee754`.

## Respaldo en Google Drive

- [Instalador exe](https://drive.google.com/file/d/1aA0YSnW3uSaaO891s5xp_AM8BF2fwjlc/view).
- [Instalador + código ZIP](https://drive.google.com/file/d/1zZK6DWg_R5kVnTGtBZOYLvo4moZDu0Oe/view).

## Bloqueo crítico pendiente

Los cerca de 600.000 dominios de HaGeZi Full **todavía no se bloquean a nivel de red**: el motor DNS auxiliar solo actualiza su caché y no se ha activado el DNS del equipo. Las políticas DoH complementan el bloqueo de navegadores y hosts; no garantizan protección frente a VPN, IP directas, apps con DNS propio ni cambios administrativos. No hay prueba end-to-end en Windows real. **No activar stable ni distribuir como versión final**.
