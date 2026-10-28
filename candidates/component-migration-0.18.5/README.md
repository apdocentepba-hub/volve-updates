# VOLVÉ 0.18.5 — recuperación DNS y migración controlada de componentes

**28 de octubre de 2026. Solo desarrollo; NO instalable como protección DNS. No publicar `stable`.**

## Cambios comprobados
- Verificación más estricta de recuperación del DNS: en Windows se comprueba que se restauró el modo original de asignación automática o manual, no solo que desapareció la dirección local.
- Validación del tipo de tarea y cadencia del rescatador independiente.
- Migración transaccional en el código: identifica los cuatro binarios originales de VOLVÉ 0.18.0, conserva el lanzador anterior, incorpora una nueva versión y rescatador inactivo, mantiene un registro de recuperación y ofrece reversión conservadora.
- Preparada la integración con preflight nativo de Windows para el actualizador, pero **la migración NO se habilitó en la interfaz del instalador**.

## Evidencia de pruebas
- Suites de Go y de concurrencia ejecutadas correctamente en Linux en los módulos principal y motor heredado.
- Compilación cruzada y análisis estático para Windows AMD64 correctos.
- Prueba de migración con archivos originales exactos de VOLVÉ 0.18.0 en directorio temporal Linux: aprobada, sin cambiar DNS ni tareas.
- **Faltan pruebas operativas en Windows real**, de recuperación de red, arranque, instalación y actualización del motor activo.

## Respaldo privado

[Fuentes y binario de laboratorio VOLVÉ 0.18.5 en Drive](https://drive.google.com/file/d/1iV9d2FS8URuz50oSNMtPgb43APy56LSw/view).

ZIP: 22.256.407 bytes; SHA-256 `f9ab294b86f3c22a8dc275302a53fbb5b75960f56181beda668d3c533c176e6f`.

**No se modificó la instalación actual del usuario. No ejecutar el binario de laboratorio encima de VOLVÉ 0.18.0: la interfaz continúa bloqueando instalaciones existentes.**

## Bloqueos antes de entregar un único setup final

Se requiere validación real del controlador de Windows y recuperación de DNS antes de habilitar la migración, activar el motor y permitir actualizaciones firmadas de componentes activos. Mantener `stable` sin manifiesto hasta alcanzar esos criterios.