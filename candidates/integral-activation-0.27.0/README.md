# VOLVÉ 0.27.0 — instalador integral experimental (29/10/2026)

**BETA Windows x64 — compilado, SIN validación end-to-end de activación y recuperación DNS real. No publicar como stable.**

Se integró el código fuente que ya superó la prueba de catálogo masivo 0.26.4 en Windows con motor DNS residente: dos listeners loopback (127.0.0.1 y ::1) UDP/TCP 53; filtro HaGeZi Full (mínimo 400.000 entradas), otras fuentes y relectura de catálogo tras actualización; reglas Chrome/Edge/Firefox/hosts; tarea horaria de catálogo; tareas SYSTEM separadas de servidor al arrancar y rescate por minuto; respaldo de asignación DNS automática original por GUID/índice; botón explícito **Instalar TODO y activar DNS** y botón **RECUPERAR DNS automático**. Se distribuye además BAT independiente.

La activación **no es automática al abrir el ejecutable**: requiere confirmación explícita UAC y solo se intenta con DNS original automático. El rescate independiente intenta restaurar DNS DHCP si el motor no responde 3 veces, y no depende del mismo proceso del servidor. Fallos en guardar el respaldo, asegurar ACL o verificar tarea detienen la activación.

Validaciones: go test ./... (OK), go test -race ./... (OK), GOOS windows GOARCH amd64 go vet (OK), cross-build GUI PE32+ x64 (OK), CRC y comprobación bytes ZIP (OK). GitHub Actions verificó forma de tarea SYSTEM y cmdlet Windows sin modificar red ([run 40870558706](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40870558706)). **NO se ejecutó el instalador 0.27 en Windows real, no se probó el cambio DNS ni la recuperación tras fallo/reinicio.** Evitar uso en máquina principal.

Integridad SHA256: `6688971bddc04042ad217de3ce82713d53fc3e8e4b21dfe2fa229ed80f3fe223`.

Archivos:
- [EXE en Google Drive](https://drive.google.com/file/d/1hCQFgM0Y7JniGUJR4TFy1GgBLP_SLoMB/view)
- [EXE y código fuente ZIP](https://drive.google.com/file/d/1h-lmQ2aFwK1tUvIHnwfc18IvOYvYV9gY/view)

Limitaciones: no garantiza evasión mediante VPN, DoH de aplicaciones, conexiones por IP ni resistencia al desinstalado; actualizador horario cambia catálogos, NO actualiza el propio EXE. La recuperación solo es compatible con DNS original automático. Mantener BAT fuera de la carpeta instalada.
