# VOLVÉ 0.15.0 BETA — Centro de protección unificado

**ESTADO: CANDIDATO. NO DISTRIBUIR AUTOMÁTICAMENTE.**

El instalador antiguo generaba accesos distintos a Panel de control, Centro de protección, Restaurar DNS y Desinstalar. Esta versión implementa un único panel nativo Windows de 64 bits con solapas:

- **Protección:** motor, DNS de Windows y catálogo reportado.
- **Diagnóstico:** motor --probe, tareas de inicio y vigilancia.
- **Actualizaciones:** estado del agente y solicitud de comprobación horaria.
- **Ayuda:** mensajes de apoyo y respiración de 60 segundos.
- **Información:** límites de cobertura y migración de accesos a uno llamado VOLVÉ.

## Migración

El botón **Unificar accesos en Inicio**, con confirmación y permiso de administrador, reemplaza solo el panel en `C:\Program Files\VOLVE\VOLVE_Centro_Proteccion.exe`, guarda copia previa, respalda accesos antiguos reconocidos y crea `VOLVÉ.lnk`. No modifica tareas de DNS, catálogo, DNS de Windows, políticas del navegador ni motor. Un desinstalador de emergencia autorizado sigue siendo externo.

## Artefactos y pruebas

- Archivo BETA (distribución privada): Google Drive, carpeta VOLVE - Actualizaciones, nombre `VOLVE_0.15.0_BETA_CENTRO_UNIFICADO.zip`
- Formato: PE64 Windows x86-64 con interfaz nativa Win32.
- Validación: `go test` y `go vet` ejecutados; estructura ZIP e integridad SHA-256 comprobadas.
- Pendiente: prueba funcional en Windows real, actualización de enlaces en el menú Inicio y persistencia tras reinicio.

**Prohibido publicar `stable/manifest.json` o `stable/manifest.sig` con este candidato** sin validación real y firma compatible con el agente existente. No anuncia versiones automáticamente y no implementa bloqueo VPN.
