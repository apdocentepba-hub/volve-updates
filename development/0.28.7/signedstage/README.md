# VOLVÉ 0.28.7 — preparación de versión inactiva (CI, no instalar)

La función `PrepareInactiveLabVersion` recibe un directorio de laboratorio con los siete componentes públicos y sus dos archivos de manifiesto/firmas. Verifica Ed25519 y SHA-256, crea una carpeta nueva exclusiva, copia con sincronización, vuelve a verificar origen y destino y realiza una promoción por renombrado, **únicamente de una versión inactiva en CI**.

No reemplaza una instalación anterior: si la carpeta destino o su estado pendiente existen, se detiene. Si la copia falla antes de la promoción, elimina únicamente los archivos temporales conocidos. El ejecutable `cmd/preparelab` exige un runner hospedado y rutas inmediatas bajo `RUNNER_TEMP`.

**El desinstalador del propietario no forma parte del paquete público.** Los controles rechazan que aparezca `VOLVE_Uninstall.exe` junto con los siete componentes.

**NO RELEASE:** esta fase no aplica ACL NTFS de producción, no crea ni activa tareas SYSTEM, no instala el motor DNS, no concede permisos de actualización y no usa firmas productivas. Faltan la instalación transaccional, watchdog persistente AtStartup, respaldos originales, autorización editorial y ensayos con reinicio de VM real.
