# VOLVÉ 0.26.1 — corrección botón de ensayo DNS (28/10/2026)
**Estado:** beta Windows x64, no probar activación real de DNS del adaptador.

## Defecto concreto en 0.26.0
La interfaz creaba el botón idRehearsal=108 pero el controlador WM_COMMAND carecía del case idRehearsal. Los clics no ejecutaban rehearsalPanel, por lo que no ocurría nada.

## Cambios 0.26.1
- Se conecta explícitamente `case idRehearsal: rehearsalPanel(w)` al manejador del botón.
- La acción lanza `--dns-recovery-rehearsal` como proceso aislado, con salida capturada y tiempo máximo de 100 s.
- Si ya hay una verificación activa, informa que debe terminar antes, en vez de ignorar el clic silenciosamente.
- Se normalizan saltos de línea a CRLF para EDIT de Win32 (antes el texto se veía concatenado).
- Migración de recibos de estado 0.26.0 y cambios de numeración visibles a 0.26.1.
- Pruebas Go y Go race aprobadas, go vet Windows amd64 y cross-build PE32+ GUI aprobados; ZIP verificado.
- SHA256 del EXE: `3d4d1f8df609d6129208270046f3a410a119687c94d2007b62337a78115700e4`.

## Entregables comprobados
- [EXE Google Drive](https://drive.google.com/file/d/1qIGz4GfcxpXt44SIi84eVhgJj2UsxRjR/view)
- [ZIP código y EXE Google Drive](https://drive.google.com/file/d/1tIkykkrIy_A6D0p-mKkd2HLjpaB6RRjQ/view)

## Límite de seguridad
La prueba usa un motor DNS temporal en loopback y un **adaptador simulado** para recuperación. No cambia DNS de Windows, no ejecuta rescate SYSTEM real ni prueba protección integral VPN/aplicaciones. No se verificó aún el clic en la computadora del usuario. No activar stable.
