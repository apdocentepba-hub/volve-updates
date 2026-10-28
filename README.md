# VOLVÉ — Canal oficial de actualizaciones

Canal previsto para Windows: `stable`, rama `main`.

## Estado del canal

**Estructura publicada; actualizaciones automáticas todavía NO habilitadas.**

El agente instalado en Windows consulta:

- `https://raw.githubusercontent.com/apdocentepba-hub/volve-updates/main/stable/manifest.json`
- `https://raw.githubusercontent.com/apdocentepba-hub/volve-updates/main/stable/manifest.sig`

Estos dos archivos **todavía no existen**, intencionalmente. No hay una nueva versión verificada para distribuir y no se debe publicar un manifiesto de prueba con una versión mayor.

## Formato y seguridad

- `public-key.base64.txt` es la clave **pública** Ed25519 que utiliza el actualizador.
- La clave **privada** no está incluida y debe permanecer fuera de GitHub, Releases, issues y registros.
- El manifiesto de versión y su firma autentican una actualización; el ejecutable verifica además el SHA-256 del paquete.
- El transporte debe ser HTTPS. La firma del manifiesto no sustituye la firma Authenticode del ejecutable Windows.
- El agente 0.14.x conocido solo permite actualizar el **panel** `VOLVE_Centro_Proteccion.exe`; no actualiza motor DNS, catálogo, instalador ni el propio agente.

## Procedimiento de una actualización REAL

1. Compilar y probar el nuevo panel en Windows x64, incluyendo controles de regresión y reversión.
2. Crear un ZIP con **únicamente** `VOLVE_Centro_Proteccion.exe`.
3. Publicar el ZIP en un Release de GitHub y obtener su dirección HTTPS real.
4. Firmar el manifiesto con `tools/firmar_actualizacion.py`, usando la clave privada almacenada fuera de este repositorio.
5. Verificar localmente versión, firma y SHA-256. Publicar **juntos** `stable/manifest.json` y `stable/manifest.sig`.
6. Probar la actualización desde el agente Windows antes de ampliar su distribución.

Las tareas horarias registradas en Windows no prueban, por sí solas, que las descargas se hayan aplicado correctamente.

**Estado actual:** canal creado y documentado, sin paquetes anunciados.
