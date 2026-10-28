# VOLVÉ 0.24.0 — Centro de protección integrado (28 de octubre de 2026)

**BETA. Panel de Windows nativo compilado, pero NO probado en una PC Windows real.** No publicar en canal estable.

## Qué se implementó
- La apertura del ejecutable sin argumentos muestra una ventana principal Win32, reemplazando el antiguo cuadro modal Sí/No/Cancelar.
- Estado consultable: políticas (incluyendo Chrome/Edge/Firefox), archivo hosts, caché de catálogo y tarea horaria.
- Botones funcionales: **Actualizar estado** (lectura asíncrona de una sola solicitud a la vez), **Diagnóstico admin** (UAC y solo lectura), **Actualizar catálogo** (UAC, invoca el motor existente con `--refresh`), **Instalar/Reparar** (UAC), **Abrir carpeta de datos**, **Cerrar**.
- Una instalación/reparación correcta copia la aplicación a `%ProgramData%\VOLVE-Browser-Filter\VOLVE_Centro_Proteccion.exe` y crea accesos directos en Inicio y escritorio público mediante WScript.Shell; no reemplaza accesos de terceros.
- Migración de recibos existentes 0.23.2; mismo motor auxiliar 0.21.0 y mismas reglas. No modifica DNS del adaptador ni requiere extensiones.
- Evita consolas visibles y consultas duplicadas por clics repetidos.

## Pruebas y limitaciones
- `go test ./... -count=1` aprobado en Linux.
- `go test -race ./... -count=1` aprobado en Linux.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...` aprobado.
- Compilación cruzada Windows x64 GUI aprobada, y compilación de pruebas Windows completada.
- ZIP pasó CRC completo y comparación byte a byte del EXE.
- SHA-256 del EXE: `7af57e5743c3057295b42d414c2d7cbd3cee069b13a06aa1fe32d30fabb74615`.
- La ventana, los accesos directos y la elevación UAC **no han sido ensayados en el PC del usuario**.
- El catálogo Full en caché no es prueba de bloqueo DNS: el motor de red permanece sin activar. No hay garantía de bloqueo en VPN ni apps con resolutor propio.
- No se ha añadido servicio residente/tray icon; el panel se puede volver a abrir desde Inicio/escritorio después de Instalar/Reparar.

## Descargas verificadas en Drive
- [Ejecutable del panel e instalador](https://drive.google.com/file/d/1QGXRTpdiAAhkfLEOExQjKIIxdK0EaQhu/view)
- [Fuentes, ejecutable y SHA-256](https://drive.google.com/file/d/1ebRyjFPkDjpNPKXP1wQO11V3vy3B_9jK/view)

No publicar `stable` hasta validación Windows y activación DNS transaccional.
