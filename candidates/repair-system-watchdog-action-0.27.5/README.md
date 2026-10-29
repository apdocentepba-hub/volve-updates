# VOLVÉ 0.27.5 — reparación administrativa de tarea de rescate (29/10/2026)

## Defecto hallado
En la captura de la 0.27.4, el watchdog SYSTEM de rescate aparece con **barras invertidas duplicadas** en la ruta del argumento File (ej. `C:\\ProgramData\\...`), mientras que el diagnóstico requiere la ruta Windows normal. Esto procede de usar `strconv.Quote` (escaping JSON/Go) para construir el argumento `schtasks /TR`.

## Reproducción y prueba en Windows CI
La ejecución [40884854657](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40884854657) aprobó la creación de una tarea SYSTEM con argumento duplicado y su corrección mediante `Set-ScheduledTask -Action`, conservando trigger y principal SYSTEM, y ejecutando efectivamente un script **ficticio**. No se modificaron DNS ni adaptadores.

## Solución 0.27.5
- Panel con botón **«Reparar SOLO tarea rescate (admin)»** y confirmación manual.
- UAC; la reparación no cambia el DNS, la caché, el motor, el archivo hosts ni las políticas.
- Antes de modificar: verifica exactamente una acción, ruta al PowerShell esperado, principal SYSTEM, y parámetros iguales a la variante heredada exacta; si algo difiere, se niega.
- Confirma SHA-256 del contenido local de los scripts watchdog/rescate contra el código original compilado.
- Guarda un respaldo del XML de la tarea protegido para SYSTEM y Administradores.
- Cambia **solo** la acción con `New-ScheduledTaskAction`/`Set-ScheduledTask`; verifica de nuevo la identidad; en caso de fallo intenta reponer los parámetros anteriores.
- La creación de tareas futuras dejó de usar `strconv.Quote` para las rutas de acciones Windows.
- Operación idempotente cuando los argumentos ya son correctos.

## Evidencias
- `go test ./... -count=1`: OK
- `go test -race ./... -count=1`: OK
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: OK
- Compilación cruzada Windows x64 GUI: OK (PE32+)
- ZIP y binario validados; SHA256 EXE: `e10a8b230b2bc0b225a0ae6d0695128c075a055266d7b323e5ee39f883788924`

## Descargas en Google Drive
- [EXE 0.27.5](https://drive.google.com/file/d/19zo_x5yMYEIvj_GIbDLVL8kc49gPvqv0/view)
- [EXE, BAT de emergencia y fuentes](https://drive.google.com/file/d/1gs_QL6B8C3a3yAope30VsMf7qUwckJZk/view)

## Limitaciones
**No probada aún esta versión en el Windows del usuario.** La reparación corrige identidad y ruta pero NO demuestra recuperación ante fallo real, suspensión, apagón o reinicio. No activar `stable`. El BAT debe conservarse fuera del directorio del motor.
