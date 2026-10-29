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

## Validación del corte forzado (GitHub Actions 40970083681)

**APROBADO:** se interrumpió con `Stop-Process -Force` el proceso independiente que había marcado `proving` y cambiado exclusivamente una tarea de prueba. Otra instancia independiente verificó el journal y el hash del respaldo, restauró el XML original y dejó el registro en `restored`. La prueba posterior alteró el XML y confirmó que su verificación era rechazada. También aprobaron la compilación Windows y las pruebas Linux.

[Logs y ejecución](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40970083681)

**Límites:** este ensayo no equivale a un reinicio real de Windows ni reproduce un corte eléctrico. Tampoco implementa aún el controlador de motor DNS para producción; no se ha instalado ninguna actualización del motor en equipos de usuarios.

## Ensayo de recuperador con trigger de inicio y cuenta SYSTEM

Se incorporó `development/0.28.7/lab/boot_recovery_lab.ps1`, estrictamente limitado a tareas de prueba con nombres `VOLVE-CI-StartupMotor-<id>` y `VOLVE-CI-BootRecovery-<id>`. En un Windows alojado por GitHub Actions: (1) se guarda una tarea inocua, (2) se modifica su ejecutable de prueba, (3) se prepara un recuperador independiente con trigger `AtStartup`, cuenta `SYSTEM`, y (4) **se ejecuta manualmente** esa tarea de inicio simulando el arranque. Se valida que la tarea original fue restaurada y que el journal quedó en `restored`.

Una segunda prueba altera el respaldo XML antes de activar el recuperador; el watchdog se niega a restaurarlo y deja intacta la tarea modificada. Las dos pruebas aprobaron junto con compilación Windows y tests Linux. [Ejecución 40973526501](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40973526501).

**No equivale a un reinicio verdadero.** Falta ensayar el arranque real de Windows en VM, comprobar ACLs del directorio de recuperación, evitar que rutas no autorizadas sean ejecutadas y luego sustituir un motor DNS real con respaldo versionado, verificación IPv4/IPv6 y control de no perder Internet. El canal estable continúa en 0.28.6; no publicar 0.28.7 como instalador.

## Laboratorio para reinicio REAL de VM (preparado, no ejecutado aún)

Archivos: `development/0.28.7/lab/vm_reboot_proof.ps1` y `development/0.28.7/lab/VM_REBOOT_README.md`. El procedimiento está limitado a una VM dedicada, comprueba hipervisor y privilegios, prepara tareas desechables exclusivamente con prefijos CI y conserva un registro de fecha de arranque. Tras **reinicio real de la VM**, una segunda sesión comprueba que el arranque es posterior al registro, que el recuperador `SYSTEM` se ejecutó y que la tarea inocua y el journal quedaron restaurados.

La validación de CI `Verify VM trial cannot pass without real reboot` debe **rechazar** la verificación en la misma sesión de arranque. Esto no constituye una prueba de reinicio real: sólo prepara un protocolo reproducible y valida las guardas. El script no ejecuta `Restart-Computer` y jamás debe correrse en la computadora personal.
