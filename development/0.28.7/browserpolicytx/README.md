# VOLVÉ 0.28.7 — motor de ensayo transaccional de políticas

Módulo de laboratorio puro Go: consume el esquema exacto de `VOLVE_Browser_Policies.json` generado desde catálogo autenticado. Requiere **772 valores** (Chrome, Edge y Firefox; 256 dominios por navegador y cuatro ajustes DoH), y rechaza planes incompletos, alterados o que afirmen permiso de instalación.

La interfaz `LabStore` es un almacén de ensayo, **no es el Registro de Windows**. `Rehearse` valida los valores y su ausencia previa, crea solo valores nuevos mediante una interfaz atómica y realiza reversión total en orden inverso incluso ante fallos de escritura. La comprobación posterior exige quedar sin valores.

### Límites

No demuestra restauración ante un corte de energía: aún no existe el journal NTFS persistente de políticas ni el driver de Registro de Windows bajo mutex SYSTEM. No ejecuta políticas en navegadores. No reemplaza comprobaciones del editor, integridad, estado del host ni la VM persistente. **No se permite publicar un Setup ni modificar Windows con este módulo.** El desinstalador propietario no forma parte del artefacto.


### Ensayo adicional de Registro REAL en Windows CI

`windows_registry_windows.go` incluye un adaptador limitado exclusivamente a `HKCU\\Software\\VOLVE-CI-BrowserPolicies-<GITHUB_RUN_ID>-<GITHUB_RUN_ATTEMPT>`. Rechaza ejecutarse fuera de GitHub Windows hospedado, rechaza reutilizar una carpeta de Registro preexistente y remapea todas las rutas de políticas originales a ese espacio de prueba. Los tests ejecutan realmente 772 escrituras, 772 reversiones y la detección de un valor ajeno. La limpieza elimina únicamente esa carpeta desechable.

No se escriben `HKLM\\Software\\Policies` ni los perfiles reales de los navegadores. No se acredita recuperación tras corte de energía, ni atomicidad de operaciones contra escritores concurrentes. Este adaptador NO debe incorporarse en un Setup productivo.

### Recuperación tras terminación abrupta (Windows CI)

`crash_journal_lab_windows.go` escribe un registro duradero de ensayo (archivo JSON con hash e `fsync`) **antes** de modificar la ubicación HKCU desechable. Un segundo proceso de Windows escribe 317 de 772 valores y termina explícitamente con código 73, sin deshacerlos. El proceso padre relee el archivo y revierte los 317 valores verificados, rechazando un journal alterado o un valor reemplazado por otro. Una segunda recuperación no modifica nada. Las pruebas se ejecutan solo en un runner Windows alojado y exigen estado PASS sin SKIP.

**No confundir** con recuperación de cortes de energía de producto: este ensayo no valida ACL NTFS persistentes bajo SYSTEM, ni firma de autorización, exclusión mutua entre usuarios, Task Scheduler en el arranque, estado de adaptadores DNS ni protección contra procesos maliciosos. No escribir en claves de navegadores reales.
