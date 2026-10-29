# VOLVÉ 0.27.4 — diagnóstico PowerShell y parámetros de rescate (29/10/2026)
**Beta de diagnóstico, sin cambios a motor DNS 0.27.0.**

## Evidencia del equipo
Diagnóstico 0.27.3 en Windows: motor DNS local bloquea y resuelve por IPv4 e IPv6; inicio SYSTEM registrado; catálogo Full presente; WINDOWS DNS no verificable porque PowerShell escribió en stderr; rescate independiente no verificable porque los argumentos son distintos.

## Código corregido
- En el script read-only del adaptador se establece `$ProgressPreference='SilentlyContinue'`.
- El decodificador acepta **únicamente** registros CLIXML de progreso genuinos en stderr con retorno exitoso, y **rechaza** cualquier salida de error, advertencia, texto libre u otros objetos; no se relaja verificación de DNS.
- Si la tarea de rescate difiere en argumentos, el diagnóstico muestra **parámetros esperados** y **encontrados** después de volver a consultar XML. No cambia la tarea ni su propietario; `confirmOwnTask` conserva igualdad estricta.
- Versión de panel 0.27.4, compatible con recibos 0.27.3, sin activar DNS al abrirse y sin cambiar ACL ni archivos de respaldo.

## Pruebas
`go test ./... -count=1`, `go test -race ./... -count=1`, `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: OK. Compilación PE32+ x64 GUI: OK; compilación de tests Windows: OK (no ejecutados). Archivo ZIP comprobado e igualdad binaria con EXE. SHA-256: `2d504c5a6362d0f0d508362361fc187e0dadaf5537eb8144a5ac07032bbd8028`.

Prueba adicional de tareas XML en Windows CI: [run 40883113389](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40883113389), confirma comparación literal posible en runner. **No demuestra que la tarea en la computadora del usuario coincida.**

## Descargas
- [EXE 0.27.4](https://drive.google.com/file/d/1KOXcvb9l36j-TtU8daEkCS_WT54t91Ff/view)
- [EXE, BAT y fuentes](https://drive.google.com/file/d/14Fa31aW5IJ27T16WYuwGRNd495Jp3Z7f/view)

## Límites
No ejecutar activación para este diagnóstico. No se ha probado esta revisión en Windows del usuario. La tarea de rescate **no** puede darse por operativa hasta comprobar y, si corresponde, reparar su configuración por una vía segura y explícita. No afirmar funcionamiento en VPN/DNS propio, ni canal estable.
