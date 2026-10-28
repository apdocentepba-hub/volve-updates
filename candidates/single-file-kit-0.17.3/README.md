# VOLVÉ 0.17.3 — kit único auto-verificable (laboratorio)

**NO INSTALAR COMO PROTECCIÓN. NO PUBLICAR `stable`.** 28/10/2026.

## Avance comprobado

- Se generó `VOLVE_0173_Kit_Unico_AutoVerificable_NO_INSTALAR.exe` como archivo **PE32+ x86-64 con subsistema gráfico** (31.044.608 bytes). Presenta ventana nativa de Windows desde el primer paso útil, sin abrir ninguna consola ni navegar por System32.
- Integra físicamente los cuatro ejecutables recompilados desde las fuentes 0.17.3: `VOLVE.exe` (lanzador), `VOLVE-06.exe` (motor DNS), `VOLVE_Centro_Proteccion.exe` (diagnóstico) y `VOLVE_Actualizador.exe` (consulta de actualizaciones firmadas por Internet).
- Agregado `setuppackage.Verify` con lista cerrada de archivos, versión, arquitectura Windows AMD64, longitud y hash SHA-256 de cada componente, rechazo de componentes faltantes, duplicados, alterados o extras.
- Agregadas 10 funciones de prueba específicas de verificación y el empaquetador reproducible `scripts/build_singlefile_lab.py`.
- El ejecutable **solo verifica y muestra un resultado**. No extrae archivos, no altera DNS, no crea tareas, no ejecuta el motor y no instala ni activa actualizaciones automáticas. El SHA interno no es una firma Authenticode.

## Validación

- 169 funciones de prueba definidas en el módulo principal y 25 en el legado = 194 definidas.
- `go test ./... -count=1` y `go test -race ./... -count=1`: aprobados en Linux en ambos módulos.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...` en el módulo principal: aprobado; vet de los paquetes independientes del motor: aprobado.
- Cinco ejecutables Windows x64 compilados de forma cruzada, incluido el kit único.
- `go run ./cmd/volve-setup --inspect` en Linux verifica los cuatro componentes incrustados.
- **Sin ejecución en Windows real** y sin pruebas de reinstalación, ACL, restauración de adaptadores, arranque, VPN o recuperación ante cortes.

## SHA-256

- Kit único de laboratorio: `c79faf0095fc668250f96f18a20a75bee8fb6a2540ac2c600382a25874826bff`.
- ZIP con fuentes + kit: `93051030f60047ab7694decd51bc2f492d8eb0a5ea1f3628ab2c88a5ea7dd9c5` (17.835.693 bytes).

## Respaldo

Carpeta privada del usuario `VOLVE - Actualizaciones` en Google Drive:

[ZIP fuentes y kit 0.17.3](https://drive.google.com/file/d/1H5PuRhijIpOmQV5xAhgP3aYOHzYwJWY5/view)

## Pendiente antes de entregar `VOLVE_Setup.exe` definitivo

1. Extracción e instalación transaccional con bloqueo global, ACL de ProgramData y Program Files, tareas SYSTEM, watchdog y comprobación real DNS.
2. Respaldo y restauración de adaptadores en una máquina Windows, incluyendo IPv4/IPv6, interfaces de VPN y DNS con DHCP; recuperación segura ante reinicios y cortes.
3. Firma Authenticode de instalador y componentes, catálogos con derechos de redistribución y pruebas end-to-end en Windows.
4. Solo después, habilitar publicación `stable` del manifiesto y firma Ed25519. El cliente 0.17.3 **solo comprueba/descarga**, todavía no aplica actualizaciones.

**No se tocó la instalación del usuario ni se activó `stable`.**