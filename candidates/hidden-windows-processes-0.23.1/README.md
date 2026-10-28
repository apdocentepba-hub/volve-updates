# VOLVÉ 0.23.1 — corrección de ventanas CMD intermitentes (28/10/2026)

**Beta para Windows x64, sin prueba end-to-end en el Windows del usuario.**

## Hallazgo
La versión 0.23.0 invocaba `reg.exe` para consultar, agregar, verificar y restaurar políticas, y `schtasks.exe` para la tarea horaria. Al compilar como aplicación GUI, esos comandos auxiliares pueden abrir y cerrar consolas brevemente, repetidas veces.

## Corrección aplicada
- Se creó `hiddenCommand` para ejecutar **todos** los procesos auxiliares del instalador (`reg.exe` y `schtasks.exe`) con `SysProcAttr.HideWindow=true` y `CreationFlags=CREATE_NO_WINDOW (0x08000000)`.
- Se verificó estáticamente que no queden invocaciones directas a `exec.Command` fuera del wrapper.
- Se agregó migración a 0.23.1 desde 0.23.0 activo y reanudación conservadora desde estado `pending`.
- Se mantuvo **sin cambiar** el motor de catálogo embebido 0.21.0 para evitar conflictos de huellas digitales en instalaciones anteriores.
- No se eliminan tareas desconocidas ni se modifica DNS IPv4/IPv6.

## Validaciones
- `go test ./... -count=1` aprobado en Linux.
- `go test -race ./... -count=1` aprobado en Linux.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...` aprobado.
- Compilación cruzada Windows x64 **GUI**, PE32+, verificada.
- ZIP de fuentes y binario probado con CRC y bytes exactos.
- SHA-256 EXE: `65a057f567b2c1b7c27466f7b6e773f463519fa2f6f27efdf3e4b5ea0bf38d76`.

## Entregables
- [VOLVE_Setup_0231_SIN_CONSOLAS.exe](https://drive.google.com/file/d/1wo9Pf9xjzhpo8BroeKvC2_llSWZfRViM/view).
- [Fuentes e instalador ZIP](https://drive.google.com/file/d/1Y_P1vWUjAlG5J_Zsa5kpVigosrVlMDxt/view).

## Restricciones
No se comprobó en Windows que desaparezcan las ventanas; puede haber otras tareas o programas que abran CMD de manera independiente. El motor DNS no se ha activado en las interfaces, y el catálogo masivo no filtra consultas a nivel de red. No publicar en stable ni afirmar protección integral frente a VPN.