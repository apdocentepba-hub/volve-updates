# VOLVÉ 0.28.7 - piloto de actualizador del motor DNS

**DESARROLLO; NO INSTALAR.** La versión operativa sigue siendo 0.28.6, que actualiza el Centro de protección desde el launcher.

Este branch conserva código Go basado en el respaldo de 0.28.5 con mejoras en desarrollo para 0.28.7. El objetivo es separar el canal del motor DNS del canal ya publicado del Centro.

Incluye comprobación de firma Ed25519, SHA-256, tamaño, versión mínima del Centro, URL restringida y preparación aislada del binario. También incluye transacción simulada y reversión sin modificaciones del servicio DNS; comando --check-motor-updates y botón avanzado "Consultar motor (piloto)".

**No existe todavía controlador real de conmutación del motor en Windows.** No publicar releases/motor-stable.json ni distribuir una actualización de motor hasta verificar restauración de tareas SYSTEM, cortes, reinicios, DNS IPv4/IPv6 y firma del paquete oficial con clave privada fuera del repositorio.

El CI prueba el nuevo módulo y compila para Windows. No genera Releases ni modifica el canal estable.
