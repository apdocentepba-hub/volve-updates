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


## Recibo editorial de instalación — paso nuevo 04/11/2026

El módulo `receipt.go` comprueba un recibo de instalación completo emitido
**después** de una instalación 0.28.7 y una verificación independiente de
recuperación tras reinicio. Requisitos innegociables:

- firma Ed25519 del recibo en bytes JSON canónicos, validada con una clave
  pública editorial previamente fijada en el producto; nunca obtenida del
  propio recibo ni elegida por el usuario en línea de comandos;
- ocho componentes, nombres y hashes, comparados con el contrato real de
  `../unifiedbundle` sin mantener otra lista divergente;
- hash de paquete firmado, respaldo DNS, journal de recuperación, tarea SYSTEM
  y acción programada, e identidad del motor 0.28.6 de origen si hubo migración;
- UUID de instalación codificado en hexadecimal, rutas Windows absolutas
  sin UNC, traversal, alias ni streams NTFS.

Una firma válida **NO demuestra** que el proceso y las tareas actualmente
ejecutándose coincidan con ese recibo. `ReviewWithSignedReceipt` devuelve
`REVIEW_AUTHENTIC_INSTALLED_0287_RECEIPT_BUT_LIVE_OWNERSHIP_UNPROVEN`
solo en condiciones conservadoras, con TODAS las operaciones destructivas
deshabilitadas y otras seis pruebas todavía obligatorias. Tareas heredadas
0.28.6 o journal de recuperación mantienen prioridad de veto.

Los tests usan claves efímeras generadas localmente para verificar tanto
casos válidos como alteraciones y suplantaciones. **No hay en este módulo
un recibo productivo emitido, firma editorial de producción disponible,
autorización de desinstalación, ni ejecutable productivo para desinstalar.**
La identidad de los objetos realmente instalados (hashes de disco, XML
de las tareas, propietario del puerto 53, DNS y lock SYSTEM) aún requiere
atestación nativa vinculada al recibo.

Evidencia Windows CI: https://github.com/apdocentepba-hub/volve-updates/actions/runs/41826124549
