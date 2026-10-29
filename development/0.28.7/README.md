# VOLVÉ 0.28.7 — Seguridad de reemplazo del motor (piloto)

**NO INSTALAR.** El canal estable y el motor DNS de la 0.28.6 no se modifican.

El código completo de referencia permanece en `complete-source-parts/` como ZIP reconstruible mediante GitHub Actions, y el archivo `VOLVE_0287_PRECHECK_RESCATE_OVERLAY_NO_INSTALAR.zip` superpone las correcciones recientes. CI verifica el SHA-256 del overlay antes de compilar.

## Avances de esta revisión

- Reversión con **contexto independiente de 90 s** cuando se cancela o supera el tiempo una actualización; no reutiliza la cancelación que provocó el fallo.
- Un nuevo comando experimental `--motor-upgrade-preflight` de **solo lectura**, que verifica que el motor y las tareas SYSTEM pertenezcan a VOLVÉ, que las acciones y los scripts de rescate coincidan exactamente, que el registro original de DNS esté activo y que respondan IPv4 e IPv6.
- Rechazo explícito de binarios vacíos, directorios, scripts modificados, tarea ajena, registro de recuperación no activo y registros con campos inesperados.
- Pruebas unitarias Windows y una prueba de cancelación con doble simulado.
- Registro de recuperación en `journal/recovery_journal.go` con fases `prepared → switching → proving → committed` y `switching/proving → restoring → restored`. El registro no contiene rutas ni comandos ejecutables, valida los hashes de motor y tarea y rechaza transiciones no autorizadas.
- Prueba con **Windows Task Scheduler real**, exclusivamente sobre una tarea inocua `VOLVE-CI-EngineSwap-<run_id>`, que cambia la acción, termina el proceso y recupera la acción original desde un proceso posterior. La tarea de prueba se retira al finalizar.
- Ejecución GitHub Actions [40967525722](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40967525722): pruebas Linux, compilación y tests Windows, recuperación de tarea de prueba — todas aprobadas.

**Importante:** el código de journal y la prueba de Scheduler todavía **no son un controlador de motor DNS para producción**. Falta integrar: (1) respaldo original de task XML y motor versionado con permisos SYSTEM, (2) recuperación independiente antes del siguiente arranque si Windows se reinicia o la máquina se apaga durante la actualización, (3) validación de tráfico DNS real IPv4/IPv6 y conectividad, (4) restauración comprobada del motor anterior, no simplemente poner DNS en automático, y (5) firma del paquete oficial y distribución escalonada. No se modificó el DNS real y el CLI piloto sigue siendo de solo lectura.

Referencia de ZIP de desarrollo: [Carpeta Drive](https://drive.google.com/drive/folders/1mV1XzqsDqAKOVuw_FWIwaOaSnWmTwt5y).

## Recuperación con journal y proceso independiente (29/10)

El paquete `VOLVE_0287_RECUPERACION_ENTRE_PROCESOS_NO_INSTALAR_v2.zip` incorpora correcciones de estado que prohíben iniciar transacciones fuera de `prepared`. Agrega un helper Go que verifica el journal, el hash del motor anterior y el XML original de la tarea antes de autorizar el rollback.

El CI de Windows realiza una prueba de laboratorio con una tarea temporal `VOLVE-CI-EngineRecovery-<run_id>`, sin tráfico DNS: guarda la tarea original, marca `switching`, conmuta el ejecutable a uno inocuo, registra `proving`, termina el proceso y **en otra ejecución de PowerShell** vuelve al original y registra `restored`. Después altera el XML para comprobar que la verificación rechaza la modificación.

**No es una recuperación probada después de reiniciar Windows**, porque el runner no se reinicia en esta prueba. Falta configurar el helper de recuperación real para arrancar de forma independiente al inicio, proteger respaldos con ACLs de SYSTEM/Administradores, controlar cortes de electricidad y verificar motor DNS real. No distribuir este piloto.

## Prueba de interrupción forzada

La nueva revisión v3 agrega una prueba más exigente en Windows: lanza el proceso del instalador piloto, espera que registre el cambio de tarea y **mata el proceso con Stop-Process -Force**. En un segundo proceso restaura la tarea original a partir del journal, verifica el hash del XML y el motor previo y rechaza un respaldo posteriormente modificado.

Esto sigue siendo un **laboratorio**, sin activar DNS ni reiniciar Windows; no demuestra tolerancia a corte de energía ni recuperación automática al arrancar la PC. El motor real y su watchdog permanecen sin modificar en 0.28.6.
