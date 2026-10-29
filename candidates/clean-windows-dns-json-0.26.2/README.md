# VOLVÉ 0.26.2 — reparación de la lectura JSON del inventario DNS (28/10/2026, AR)
**Beta para Windows 64 bits. No cambia la configuración DNS de Windows.**

## Fallo observado en la PC
El botón “Ensayar activación / rescate” se ejecutó en la 0.26.1, pero el resultado fue:
`invalid character '#' looking for beginning of value`.

El código anterior ejecutaba `powershell.exe -EncodedCommand` usando Go `CombinedOutput()`, mezclando JSON de stdout y mensajes de PowerShell/CLIXML de stderr. No demuestra un error de la red ni del catálogo.

## Reparaciones
- `CaptureOriginalDNS` usa ahora `cmd.Stdout` y `cmd.Stderr` separados, manteniendo ocultas las ventanas auxiliares.
- Script de PowerShell envuelve el inventario de solo lectura con `try/catch`, emite un único JSON mediante `[Console]::Out.WriteLine`, registra errores por `[Console]::Error.WriteLine` y retorna exit code 8 si falla.
- Parser estricto de JSON que acepta UTF-8, BOM UTF-8, UTF-16LE y UTF-16BE (cuando corresponda). Rechaza texto adicional, JSON parcial, errores en stderr, direcciones DNS no aptas y configuraciones ambiguas.
- Pruebas añadidas para salida con BOM, salida con CLIXML/error, mensajes adicionales, IP de loopback y PowerShell sin datos.
- Conserva el botón conectado en 0.26.1 y compatibilidad de estado con esa versión.

## Verificación
- `go test ./... -count=1`: OK (Linux).
- `go test -race ./... -count=1`: OK (Linux).
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: OK.
- Compilación cruzada Windows GUI PE32+ x64: OK.
- **GitHub Actions Windows real (Windows PowerShell 5.1)**: ejecución de la captura read-only equivalente, con stderr separado y salida JSON comprobada: [run 40798108258](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40798108258), conclusión success.
- ZIP verificado CRC e integridad de EXE; SHA-256: `fb47811a005c352d583388a9582137f2c72d3f6af102d19db4f2a698df79beba`.

## Descargas
- [Instalador beta 0.26.2 en Google Drive](https://drive.google.com/file/d/1fiwwpL-lyRXI4S1Cy4pWDpT_7WK4wlRl/view).
- [Código y ejecutable ZIP](https://drive.google.com/file/d/1wsyvHtoXlefLsVLgZDnFr3YCBcvXQCpq/view).

## Limitaciones
No se ha ejecutado la 0.26.2 en la computadora del usuario. El ensayo continúa usando un adaptador **simulado** para la reversión. No modifica el DNS de Windows ni habilita el filtro en todo el sistema. Una prueba correcta de lectura DNS no certifica recuperación real ante un reinicio ni protección general frente a VPN.
No publicar `stable`.
