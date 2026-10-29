# VOLVÉ — Canal oficial de actualizaciones de Windows

## Centro de protección (0.28.5 en adelante)

**Canal de actualización firmado activo para el panel: VOLVÉ 0.28.6 (piloto).**

El Centro consulta estos dos archivos de la rama principal:

- `https://raw.githubusercontent.com/apdocentepba-hub/volve-updates/main/releases/stable.json`
- `https://raw.githubusercontent.com/apdocentepba-hub/volve-updates/main/releases/stable.json.sig`

El manifiesto está firmado con Ed25519 y la clave pública está incorporada en el cliente. El cliente comprueba la firma, la versión, el tamaño y el SHA-256 del ejecutable antes de ofrecer la actualización. El programa anterior conserva su copia al instalar una nueva versión y, al aplicar el cambio, requiere permisos administrativos de Windows.

**Límite de esta actualización:** solo instala una nueva versión del Centro de protección. **No actualiza ni reinstala el motor DNS, el watchdog, el instalador integral, los bloqueos de VPN o las tareas de rescate.** Estos componentes siguen requiriendo su propio mecanismo de actualización y validación.

## Publicación 0.28.6

- [Release de prueba v0.28.6](https://github.com/apdocentepba-hub/volve-updates/releases/tag/v0.28.6)
- [Integración de instalación 0.28.5 → 0.28.6 aprobada en Windows de GitHub](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40927834477)
- SHA-256 del ejecutable: `8659d948427e515e3471508487c81afadb6c9cecfd3633aedc6ea67459f1d72a`

Validado: versión anterior instala el panel nuevo en un Windows temporal con privilegios administrativos y genera el acceso directo correcto. Pendiente: confirmación del botón y flujo UAC en una PC del usuario, pruebas de protección DNS real y firma Authenticode para Windows.

El archivo `releases/stable.json` y su firma se publicaron juntos. Para próximas versiones, primero subir el binario, validar descarga e instalación, luego firmar fuera de línea y publicar ambos archivos en el mismo commit. No subir la clave privada.

## Agente anterior (0.14.x)

El canal legado `stable/manifest.json` y `stable/manifest.sig` es distinto del canal moderno y permanece inactivo. No se debe mezclar su clave con el canal 0.28.x. Si se habilita en el futuro, requiere una revisión de compatibilidad independiente.
