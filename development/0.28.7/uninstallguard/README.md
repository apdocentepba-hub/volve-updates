# VOLVÉ 0.28.7 — Uninstaller ownership guard (NO DESINSTALA)

Capa de revisión preventiva para el futuro desinstalador único. No contiene
funciones que eliminen archivos, tareas, políticas, servicios o DNS.

En la PC real observada en noviembre 2026 existen las tareas heredadas
`VOLVE-CATALOGO-0230`, `VOLVE-DNS-RESCUE-0270` y
`VOLVE-DNS-SERVER-0270`, además del motor DNS activo.
Por diseño, el estado resultante es `STOP_LEGACY_0286_PROTECTION_PRESENT`.

Un eventual desinstalador productivo deberá verificar por separado una
instalación 0.28.7 firmada, la identidad exacta de cada archivo/tarea,
respaldo de DNS y XML de tareas, lock SYSTEM, journal de transacción,
watchdog externo, reversión probada y consentimiento explícito.

**Este paquete NO es un desinstalador productivo** ni un cuarto
componente aprobado del futuro Setup. Ninguna salida autoriza acciones.
