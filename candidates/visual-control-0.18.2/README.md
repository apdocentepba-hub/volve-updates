# VOLVÉ 0.18.2 — Centro Visual portátil de diagnóstico (28/10/2026)

**Ejecutable para Windows x64, interfaz gráfica persistente, modo SOLO LECTURA. No es instalador completo ni activa el DNS.**

Se creó el primer panel portátil separado de la instalación beta 0.18.0, con ventana nativa Win32/GDI diseñada para evitar el flujo previo de tres ventanas MessageBox. Incluye cuatro secciones operativas: **Inicio**, **Motor DNS**, **Instalación**, **Actualizaciones**.

### Funcionalidad real
- Detecta versión y modo de instalación en `%ProgramFiles%\VOLVE\state`.
- Comprueba archivos de lanzador, motor, panel y actualizador.
- Consulta únicamente (`schtasks /Query`) la tarea de actualizaciones y las tareas heredadas del DNS y watchdog.
- Envía consultas UDP de prueba al DNS loopback `127.0.0.1:53` y `[::1]:53`; verifica dominio de prueba bloqueado y dominio permitido.
- Consulta bajo demanda `stable` por HTTPS y valida Ed25519 con clave pública anclada, sin descargar o instalar.
- Guarda un reporte TXT **solo cuando el usuario lo solicita**.
- Todas las comprobaciones permanecen no invasivas. No se piden permisos de administrador ni se cambian DNS, servicios, adaptadores, navegador o tareas.

### Compilación / validación
- `go test ./... -count=1`: pasó.
- `go test -race ./... -count=1`: pasó.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: pasó.
- Compilación cruzada Windows x64 GUI (PE32+): pasó.
- **No se probó la interfaz ejecutándola en Windows**, de modo que podría requerir ajustes visuales.

### Archivos privados de trabajo
- [Ejecutable portátil](https://drive.google.com/file/d/1ZWlkEA0HFTYZvf8mP5BXokamc1M4pVca/view) (5,5 MB) SHA-256 `bdb6cb4740359dff33a8ccb4ad797d90e0f95a21b033df258ffceeb54f13ec9f`.
- [Código y binario de respaldo](https://drive.google.com/file/d/1Tz9BGsBmTz9Gx0NdjUwO5nzcGy55d1Ro/view) SHA-256 `f36dc4016f8b81cab3bdca3007f63496ce16074704e49b51be183ecf63600f2c`.

### Estado y próximos pasos

La instalación beta 0.18.0 en la PC del usuario muestra archivos copiados, pero **no tiene motor DNS activo verificado**. Esta versión 0.18.2 permite ver el estado real sin sustituir la beta existente.

Queda pendiente un instalador único que migre versiones anteriores, active DNS sin perder conectividad, instale/recupere watchdog, firme releases y aplique actualizaciones remotas con rollback probado en Windows real. Mantener `stable` sin publicar.
