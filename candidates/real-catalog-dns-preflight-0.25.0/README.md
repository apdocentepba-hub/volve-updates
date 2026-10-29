# VOLVÉ 0.25.0 — Prueba DNS real con catálogo masivo (29/10/2026, Argentina)

**Estado:** beta Windows x64; no cambiar el DNS del sistema ni activar canal estable.

## Cambios implementados
- Partiendo de la versión 0.24.1 que ya abrió y respondió en Windows, se incorpora un botón de **Probar DNS local con catálogo completo (sin cambiar Windows)**.
- La comprobación se ejecuta en un proceso aislado, sin consola, con límite de 65 segundos y sin bloquear la interfaz Win32.
- Lee directamente el archivo `%ProgramData%/VOLVE-Browser-Filter/catalog/feeds/hagezi_gambling_full.txt` y requiere **al menos 400.000 dominios válidos**; nunca se confía solo en el contador de `estado.json`.
- También carga los otros archivos de fuentes válidos, usa el mismo algoritmo de normalización y coincidencia por sufijo de `blocker`, e inicia `dnsproxy.Server` real en un puerto temporal `127.0.0.1`.
- Verifica **NXDOMAIN de un dominio real del archivo Full**, respuesta permitida con upstream sintético local y bloqueo **TCP**. Ejecuta prueba UDP opcional en `::1`.
- Comprueba si UDP y TCP en `127.0.0.1:53` están libres, abriéndolos y cerrándolos de inmediato, sin sustituir ningún proceso ajeno.
- Todas las comprobaciones usan loopback y un upstream local simulado. No envía consultas DNS de prueba a Internet, no modifica adaptadores DNS, cortafuegos, servicios, tareas ni reglas por probar.

## Resultados comprobados
- Tests principales de Go: OK.
- `go test -race ./...`: OK.
- Prueba de motor y caché con **400.100 dominios sintéticos** e intercambios UDP/TCP: OK.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: OK.
- Compilación PE32+ GUI x64: OK; compilación de tests para Windows: OK (no ejecutados).
- ZIP verificado CRC y correspondencia byte por byte del ejecutable.
- SHA-256 EXE: `b3b898fcef17ad76da77a2814d02354a84d7208e302c79cf2822a748be042a5a`.

## Descargas
- [Ejecutable 0.25.0 en Drive](https://drive.google.com/file/d/1qe-5rqDuAJnpMbBZ5pzHuPe9_OClHI4Y/view).
- [Código y ejecutable 0.25.0](https://drive.google.com/file/d/1pgA9bq_dH9rWLXBkBzjfUet2T-nVtppo/view).

## Próximo bloqueo
Esta versión no configura Windows para consultar el filtro en puerto 53. Antes de activar los DNS IPv4/IPv6 de los adaptadores hace falta validar en VM Windows el watchdog independiente del instalador, conservación del DNS original, conectividad del motor, corte simulado, restauración y reinicio. **No afirmar protección DNS masiva de todo el sistema**; apps con DNS propio y VPN continúan fuera de la garantía actual.
