# VOLVÉ 0.27.1 — diagnóstico real y prueba integrada de 100 dominios

**29/10/2026 — Windows x64 — beta de diagnóstico. No cambia DNS al abrirse.**

## Sobre la instalación 0.27.0
En la computadora del usuario se observó el DNS del adaptador con `127.0.0.1` y `::1`, respuestas permitidas para `example.com`, y NXDOMAIN para `bet365.com` consultando directamente ambos resolutores locales. Una muestra de 100 dominios de HaGeZi Full dio 100 respuestas compatibles con bloqueo. **No hay validación de persistencia después de reiniciar ni recuperación real ante caída del motor.**

## Mejoras en el código
- Botón «Comprobar protección REAL»: proceso de solo lectura con límite de 85 s, lee journal activo, prueba el motor por IPv4/IPv6, verifica con PowerShell el adaptador original identificado por GUID y comprueba que utilice exclusivamente loopback DNS; verifica identidad de tareas SYSTEM y antigüedad de la fuente Full. Errores de permisos se informan como «NO VERIFICABLE», no como fallo demostrado.
- Botón «Probar 100 dominios en vivo»: selección aleatoria de 100 dominios efectivamente bloqueables en el motor cargado desde el catálogo Full; 50 consultas UDP al DNS local IPv4 y 50 a IPv6, con límites de tiempo y respuesta resumida. Nunca abre páginas ni envía solicitudes HTTP de apuestas. NXDOMAIN no equivale por sí solo a evidencia de sitio existente.
- Los informes del catálogo ya no declaran falsamente DNS desactivado, y el botón de actualización muestra estado condicionado a la instalación real.
- El programa es compatible con estado 0.27.0. Se puede ejecutar solo como panel para ver nuevos diagnósticos **sin reinstalar, sustituir ni detener el motor 0.27.0 activo**.
- El BAT independiente de DNS automático se conserva por separado.

## Pruebas comprobadas
- `go test ./... -count=1`: aprobado.
- `go test -race ./... -count=1`: aprobado.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: aprobado.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags='-H windowsgui -s -w'`: aprobado (PE32+ Windows x64).
- ZIP completo probado con CRC y ejecutable comparado byte a byte.
- SHA-256 EXE: `bed06da26afffd1b2346a35c3685cfba12194ec7356264e8b2a6c4d05fa471b5`.

## Archivos de Google Drive
- [EXE 0.27.1](https://drive.google.com/file/d/1eeZ4jaCvOwb94MVC1el2tfzClAiKLqtY/view)
- [EXE, BAT de rescate y código ZIP](https://drive.google.com/file/d/1NZGfwOr44r2mjo-BHm3ffK_ol8rzBNnw/view)

**Limitación:** no se ha ejecutado esta compilación en Windows real ni se ha verificado aún el rescate al caer el motor. No activar `stable`, ni proclamar resistencia a VPN, DoH externo o DNS propio de aplicaciones.
