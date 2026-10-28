# VOLVÉ 0.18.1 — revisión de interfaz gráfica, laboratorio (28/10/2026)

**NO INSTALAR SOBRE VOLVÉ 0.18.0 EXISTENTE. NO ACTIVAR stable. NO CONFUNDIR CON PROTECCIÓN DNS.**

## Diagnóstico con capturas de Windows

La versión 0.18.0 mostraba tres MessageBoxW (confirmar, archivos instalados y diagnóstico). El mensaje de instalación informó archivos en `C:\Program Files\VOLVE`, pero el panel de diagnóstico informó que el filtro local no estaba verificado por timeout del DNS `127.0.0.1:53`. Es coherente con una beta que instala componentes sin iniciar motor ni modificar adaptadores, y no cumple el instalador gráfico completo solicitado.

## Código desarrollado en 0.18.1

- Sustituye las ventanas MessageBox de instalación por un asistente Win32 visible con barra de progreso, seis etapas de trabajo, solicitud UAC e informes de error/resultado en la misma ventana. Estado final explícito: componentes instalados, filtro DNS **inactivo**.
- Reemplaza el popup de diagnóstico por un centro Win32 con botón `Volver a comprobar` y pruebas separadas del DNS IPv4 e IPv6. No afirma que un test de loopback pruebe resistencia a VPN o DoH.
- Si ya existe `Program Files\VOLVE`, deshabilita el botón de instalación, evita sobrescrituras, y explica que aún no existe una migración segura.
- Mantiene el instalador en modo `components-only`; no modifica DNS, no arranca el motor y no activa cambios al filtro. **No es actualización instalable de la versión 0.18.0 que el usuario tiene.**

## Validación

- Compilación PE32+ Windows GUI x64: correcta; instalador 33.446.912 bytes, SHA-256 `9f5c2b4b39a7a6013c64ebe923dfc77c9de618fe7e2a3c71a6c4b8e204ccf260`.
- Manifiesto integrado: 4 componentes verificados; package `0.18.1`.
- `go test ./... -count=1`, `go test -race ./... -count=1`: OK en Linux módulo principal; suites del motor legado OK en Linux con y sin race.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: OK en módulo principal.
- Windows cross-build de pruebas de `winsetup`: OK; **GUI no ejecutada en Windows real**, por lo que la experiencia visual no está aún validada.

## Backup privado

[ZIP con fuentes y binario de laboratorio](https://drive.google.com/file/d/1adlVEv0o2ACGmTUf4nuFy9A_dxEy5Sxq/view), 35.092.320 bytes; SHA-256 `d13b9aba1748cc4142ffc89f7e39f3cea52fb7781c93607d17dea12166a5d719`.

## Impedimentos para un producto completo

1. Migrar una instalación existente, motor DNS y watchdog con recuperación real antes y después del cambio.
2. Demostrar en Windows arranque, tareas, ACL, DNS IPv4+IPv6, caídas, reinicios y rollback.
3. Integrar actualizaciones firmadas que puedan reemplazar de forma segura motor y demás componentes activos; publicar un primer paquete real y validado.
4. Finalizar catálogo y controles de navegación y documentar límites frente a VPN/DoH.
5. Firmar editor/instalador y verificar su comportamiento en Windows real.

**No se modificó la computadora del usuario; stable continúa desactivado. El ZIP no está destinado a instalación.**