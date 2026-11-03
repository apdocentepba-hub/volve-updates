# VOLVÉ 0.28.7 — verificación del paquete único

**No es un instalador ni un motor liberado.** Este módulo comprueba los
ocho componentes obligatorios (Centro con actualizador, motor DNS, manifiesto
y firma del motor, watchdog SYSTEM, desinstalador, políticas de navegadores,
catálogo Full) antes del empaquetado privado en un único `VOLVE_Setup.exe`.

Un `manifest.json` firmado externamente con Ed25519 y `manifest.ed25519`
fija nombres exactos, versión, arquitectura, tamaños y SHA-256. El llamador
debe aportar la clave pública editorial confiable **fuera del paquete**.
Se rechazan componentes omitidos, adicionales, duplicados, alterados,
versiones antiguas, rutas ajenas y enlaces simbólicos.

`go test ./...` ejecuta pruebas de éxito y de rechazo con claves **sintéticas**.

No contiene fuentes privadas del instalador 0.18.5 ni secretos. No escribe
DNS, tareas, políticas ni archivos instalados. Antes de una instalación,
se debe copiar a un área privada NTFS y **revalidar la copia**. Falta
integración transaccional, firma auténtica del editor y ensayos con reinicio
de la misma VM Windows. Ninguna prueba de este módulo autoriza una release.
