# VOLVÉ 0.18.0 — instalador beta de componentes, con actualización firmada automática en modo sin DNS

**28/10/2026 · DESARROLLO / BETA, NO APTA PARA REEMPLAZAR PROTECCIÓN INSTALADA. NO PUBLICAR `stable`.**

## Código desarrollado

- Primer instalador gráfico real para Windows x64: `VOLVE_Setup_0180_BETA_COMPONENTES_SIN_DNS.exe` (33.397.760 bytes). Muestra confirmación con alcance exacto, pide UAC, comprueba SHA-256 y PE64 de 4 componentes, copia al directorio de versión bajo `Program Files\VOLVE` y verifica el resultado después de copiar.
- **Se niega a sobrescribir una instalación previa** bajo `Program Files\VOLVE`. Ni borra ni modifica el DNS/los scripts antiguos. La migración del motor y watchdog anteriores sigue sin validación en Windows.
- Lanza el panel mediante un único `VOLVE.exe` permanente y registra `VOLVE-Actualizaciones` una vez por hora; con restauración comprobada de la tarea si la creación o comprobación fallan. El motor DNS se copia, **pero no se inicia ni cambia los adaptadores**.
- El agente `--agent --run` conserva la comprobación HTTPS de paquetes firmados con Ed25519 y clave pública fija. Las instalaciones nuevas estrictamente `components-only` pueden aplicar **actualizaciones de archivos dormantes** con versión transaccional y rollback si los binarios y su `--selftest` fallan. Primero inspecciona tareas y DNS reales y rechaza la activación automática si detecta motor/watchdog antiguo o DNS local configurado.
- El canal estable continúa sin manifiesto público. **Actualmente no hay ningún paquete remoto publicado** ni actualización que se pueda aplicar. La activación automática no significa que el motor DNS esté protegido.

## Validación

- 176 funciones Test* en módulo principal y 25 en el motor: **201 funciones definidas**. Suites ejecutadas y aprobadas en Linux, incluido modo `-race` para los dos módulos.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: correcto en módulo principal. Comprobaciones para paquetes Go independientes del motor también correctas.
- Cinco ejecutables PE32+ x64 recompilados, incluido instalador GUI. Prueba real de **copia de componentes en carpeta temporal Linux** aprobada: contenido, estado, hash, marcador y rechazo de sobreescritura.
- **No se ha ejecutado un proceso de instalación ni rollback real en Windows**, y no se hizo ninguna modificación a la PC del usuario. El controlador DNS y la migración del watchdog no son seguros para activar todavía.
- SHA-256 del instalador: `1a9fb78323ed9a65830e96726f5172596edacf62ea6fb8baa14fdba52df107f9`.

## Archivos y privacidad

Respaldo de fuentes y binarios en Drive del propietario:
- [ZIP 0.18.0](https://drive.google.com/file/d/1qxPzTeXmhPtrP-HUU43Ss0en27KrStkf/view)
- [EXE beta de componentes](https://drive.google.com/file/d/16gAD4vBwLfVXjEVYFhg7AcqfZoZ_SFNd/view)

**No hay código fuente ni claves privadas publicados en este repositorio público.** No alterar las claves Ed25519, no activar `stable` ni declarar completa la protección sin pruebas Windows.

## Pendiente para instalador único final

1. Migración transaccional de instalación antigua, tareas motor/watchdog y DNS con restauración garantizada.
2. Pruebas end-to-end en Windows real, reinicios, fallos de red, IPv6, VPN/DoH y respuesta DNS.
3. Panel final y catalogación de reglas de navegadores, actualización del motor activo, permisos ACL y firma Authenticode.
4. Publicación segura de una primera release realmente probada, con manifiesto y firma, para encender el canal automático.

Este instalador **instala archivos y tareas de búsqueda de actualizaciones, pero no activa protección DNS**. Si ya existe VOLVÉ, se detendrá para evitar reemplazo inseguro.