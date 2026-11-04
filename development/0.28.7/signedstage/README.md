# VOLVÉ 0.28.7 — preparación de versión inactiva (CI, no instalar)

La función `PrepareInactiveLabVersion` recibe un directorio de laboratorio con los siete componentes públicos y sus dos archivos de manifiesto/firmas. Verifica Ed25519 y SHA-256, crea una carpeta nueva exclusiva, copia con sincronización, vuelve a verificar origen y destino y realiza una promoción por renombrado, **únicamente de una versión inactiva en CI**.

No reemplaza una instalación anterior: si la carpeta destino o su estado pendiente existen, se detiene. Si la copia falla antes de la promoción, elimina únicamente los archivos temporales conocidos. El ejecutable `cmd/preparelab` exige un runner hospedado y rutas inmediatas bajo `RUNNER_TEMP`.

**El desinstalador del propietario no forma parte del paquete público.** Los controles rechazan que aparezca `VOLVE_Uninstall.exe` junto con los siete componentes.

**NO RELEASE:** esta fase no aplica ACL NTFS de producción, no crea ni activa tareas SYSTEM, no instala el motor DNS, no concede permisos de actualización y no usa firmas productivas. Faltan la instalación transaccional, watchdog persistente AtStartup, respaldos originales, autorización editorial y ensayos con reinicio de VM real.


## Recuperación de copia interrumpida — 04/11/2026

El módulo `RecoverAbandonedInactiveLabStage` complementa la preparación inactiva. Ante un cierre abrupto mientras se crea `VOLVE-CI-VERSION-*.pending`, exige el manifiesto original íntegro y firmado, controla la ausencia de destino ya preparado, toma un lock exclusivo de recuperación y valida **todos** los archivos conocidos antes de retirar únicamente el pendiente.

Acepta archivos truncados solo cuando sus bytes son un prefijo idéntico al original firmado. Rechaza archivos alterados, adicionales, enlaces, `VOLVE_Uninstall.exe`, un editor diferente, un lock preexistente o destino ya presente. No usa borrado recursivo; ante anomalías preserva la evidencia.

El comando `cmd/preparelab --recover-pending` está limitado a runners descartables de GitHub y no se distribuirá. CI ensaya recuperación de copia interrumpida y reintento de preparación, sin modificar tareas SYSTEM, servicios ni DNS.

**Límites:** esto no es todavía el recuperador productivo después de reiniciar el equipo, ni reemplaza la transacción SYSTEM y el watchdog externo. Se requiere atestación nativa bajo ACL NTFS y bloqueo global antes de integrarlo a una instalación real.
