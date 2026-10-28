# VOLVÉ 0.18.8 — Seguridad de rescate y primera prueba Windows

**28/10/2026 — Solo desarrollo; NO instalar ni publicar `stable`.**

## Correcciones del motor de rescate
- Antes de registrar tareas de rescate SYSTEM, se comprueba si existe alguna tarea con el mismo nombre. Una tarea ajena, una respuesta ambigua o un error de consulta detienen el proceso; nunca se la sobreescribe.
- La recuperación del DNS comprueba GUID e índice de la interfaz original, sin depender del nombre visual que Windows permite cambiar.
- Se añadieron pruebas de regresión para las consultas de tareas: presencia, ausencia, mensajes ambiguos y errores. Se compilaron las pruebas para Windows x64; sus casos comunes se ejecutaron sobre Linux.

## Pruebas ejecutadas
- Suite principal Go, suite con `-race` y módulo del motor DNS: aprobados.
- Análisis estático y compilación cruzada para Windows: aprobados.
- **Windows Server 2025 alojado por GitHub Actions**: tareas de prueba SYSTEM con repetición de 5 minutos y ejecución al inicio, verificación exacta de tipos de activadores y eliminación de tareas temporales: **APROBADO**. [Ver ejecución real](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40766243840).
- Auditoría **solo lectura** de adaptadores DNS en Windows: [ver ejecuciones](https://github.com/apdocentepba-hub/volve-updates/actions/workflows/volve-windows-dns-audit.yml). **APROBADA** después de separar los adaptadores físicos de los virtuales y omitir interfaces sin pila IPv4. Se validó la lectura del modo automático/manual y la identificación por GUID en Windows Server 2025. [Ver ejecución aprobada](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40766912421). La VM también tiene adaptadores virtuales; no se modificó ninguna configuración DNS.

## Respaldo privado

[Código y pruebas 0.18.8 en Drive](https://drive.google.com/file/d/1Q3r2ObTDYMdqGyC8AtsVEaiuTQ2WovQd/view) — 19.234.711 bytes; SHA-256 `926c6759efd989d0970c00d7088395dd05efd2dec4258b8569822c1fbc86b75d`.

## Todavía no finalizado
El motor NO se activó en Windows real ni se validó recuperar DNS después de un corte; tampoco se habilitó la migración 0.18.0 desde el asistente ni la actualización firmada del motor activo. La PC del usuario permanece sin cambios. No distribuir el binario de laboratorio como instalador definitivo.