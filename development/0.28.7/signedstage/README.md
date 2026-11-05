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


## Exclusión entre procesos — 04/11/2026

La preparación y la recuperación **comparten un bloqueo del sistema operativo por destino**, adquirido antes de leer o crear el estado pendiente y liberado después de finalizar el proceso o las limpiezas de error. En Windows se utiliza un mutex con nombre del kernel vinculado al hilo del proceso; si el proceso termina de forma inesperada, Windows libera su propiedad automáticamente. En Linux/macOS, el ensayo usa un bloqueo consultivo `flock` liberado al cerrar el descriptor del proceso.

Se prueba que una recuperación o segunda preparación concurrente se rechacen mientras hay un escritor activo y que el bloqueo se pueda adquirir nuevamente cuando el proceso de prueba termina sin liberarlo. No sustituye un mutex global SYSTEM, las ACL NTFS ni la recuperación editorial firmada de producción. **Esta funcionalidad permanece CI-only, sin instalar, borrar o modificar el motor residente.**
