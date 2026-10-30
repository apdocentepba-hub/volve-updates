# VOLVÉ 0.28.7 — Porcentajes controlados de los pasos 2 y 3

Fecha de corte inicial: 30/10/2026. Rama de desarrollo: feature/motor-updater-0287-pilot. **No es una certificación de funcionamiento en producción**.

## Cómo se calculan

Las cifras son **estimaciones conservadoras de ingeniería por entregables ponderados**, no una medición del tiempo, ni una cantidad de líneas, ni un porcentaje de protección. Se acumula crédito parcial por código efectivamente integrado y verificable; aprobar CI no reemplaza los ensayos sobre un equipo Windows persistente. Nunca publicar como cerrado un paso que no haya aprobado todos sus criterios obligatorios.

### Paso 2 — Actualización del motor DNS: 43/100 (43%)

| Subentregable | Peso | Puntos reconocidos | Estado |
| --- | ---: | ---: | --- |
| Permiso editorial exacto, autenticidad y pinning | 15 | 8 | Validación criptográfica en CI; falta emisión legítima para el motor instalado |
| Respaldo anterior y journal protegido | 15 | 15 | Código y auditorías NTFS probados |
| Watchdog de recuperación SYSTEM independiente | 25 | 5 | Lab descartable; NO hay watchdog productivo |
| Controlador Windows real que cambia y revierte el motor | 20 | 0 | Bloqueado expresamente |
| Tests adversos, DNS dual-stack, identidad, rollback en CI | 15 | 15 | Motor compilado ejecutado bajo SYSTEM en DNS/53 real y sondeado externamente en VM descartable; faltan escenarios productivos |
| Reinicio real repetible de VM persistente | 10 | 0 | Sin ejecutar |
| **TOTAL** | **100** | **43** | **Paso abierto** |

Los seis criterios A–F de STEP2_EXIT_CRITERIA.md siguen sin aprobarse **como condiciones de cierre completas**, aunque hay subtrabajos de esos criterios realizados.

### Paso 3 — Recuperación automática: 30/100 (30%) — CI de política aprobada

| Subentregable | Peso | Puntos reconocidos | Estado |
| --- | ---: | ---: | --- |
| Journal durable y estado recuperable | 15 | 10 | Probado; terminal create-only |
| Recuperación independiente de prueba | 20 | 10 | Pruebas Windows con tareas descartables |
| Política de recuperación al iniciar, bloqueo de concurrencia, reintentos | 15 | 10 | **CI 3/3 aprobada; integración de mutex Windows y watchdog productivo pendiente** |
| Watchdog SYSTEM persistente con arranque Windows | 25 | 0 | Ausente |
| Restitución productiva y comprobación de motor/DNS/Internet | 15 | 0 | Ausente |
| Pruebas de reinicio real en VM persistente | 10 | 0 | Ausente |
| **TOTAL VERIFICADO** | **100** | **30** | **Paso abierto** |

**Trabajo de esta intervención:** \`resident_boot_recovery.go\` y \`resident_boot_recovery_test.go\` agregan una política repetible y no mutante de recuperación al arranque: exige bloqueo exclusivo, respaldo íntegro, journal pendiente, restaurador inyectado y comprobación de identidad/DNS/Internet antes de cerrar el journal. Los tests incluyen fallo del restaurador, caída de red, reintento tras interrupción, concurrencia, corrupción del journal y no repetición de tareas terminadas. Es exclusivamente lógica reutilizable, **NO** un watchdog SYSTEM instalado. La ejecución [#41107808258](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41107808258) terminó **3/3 success** (Windows, Linux, recuperación aislada). Se acreditan **10 de 15 puntos** del subentregable "política de recuperación": el paso 3 se actualiza al **30%**. Los 5 puntos restantes dependen de integrar un controlador persistente real. La prueba de mutex entre procesos es una nueva subetapa aún pendiente de CI, por lo que no agrega puntos.

Ver [CI actual de la política](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41107808258). La última batería completa verde anterior fue [#41106287730](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41106287730).

## Qué no debe confundirse

- Un simulador de recuperación **no** constituye restauración tras reinicio real.
- Un binario compilado para Windows **no** acredita que se ejecutó con éxito en Windows.
- Un journal "pendiente" **no** es una autorización editorial para conmutar el DNS.
- No declarar 100% hasta verificar con criterios de aceptación, reproducir fallos, reiniciar una misma VM real y documentar reversión.
- No tocar \`main\`, \`stable.json\`, \`motor-stable.json\`, las credenciales, el servidor DNS productivo ni la instalación VOLVÉ 0.28.6 del usuario sin los controles y autorizaciones correspondientes.


## Avance nuevo: exclusión de procesos Windows para recuperación — 30/10/2026

- Se incorporó a la rama piloto un mutex nativo de Windows (`Global\\VOLVE-CI-BootLock-<id>`) para que un watchdog de laboratorio obtenga un bloqueo **entre procesos** antes de restaurar una tarea descartable. El mutex está restringido por nombre a la familia `VOLVE-CI-*` y sigue existiendo un rechazo expreso de la tarea productiva.
- El contrato de recuperación al arrancar (`ResidentBootRecoveryDriver.AcquireExclusive`) exige una exclusión antes de leer el journal, restaurar y confirmar el resultado. El restaurador independiente de tareas descartables ahora utiliza el mutex en su ruta de ejecución. La tarea productiva NO está habilitada ni registrada.
- Se corrigió un detalle de concurrencia fundamental: un mutex nativo pertenece a un **hilo de Windows**, de modo que su propietario Go queda fijado al mismo hilo hasta liberarlo; `sync.Once` evita cerrar o soltar dos veces el manejador.
- Pruebas nuevas de Windows: dos procesos independientes disputan el mutex, el segundo espera; el propietario termina abruptamente y el mutex abandonado debe recuperarse; cancelación bajo contención; nombre ajeno/productivo rechazado; desalojo seguro sin journal. Estas pruebas NO alteran tareas SYSTEM ni la red.
- CI de integración actual: https://github.com/apdocentepba-hub/volve-updates/actions/runs/41109499297. **Pendiente resultado Windows definitivo.** El marcador continúa en paso 2 **40%**, paso 3 **30%**. Esta mejora aún no suma puntos porque no implica watchdog productivo ni reinicio real.


## Corrección y prueba de cierre del mutex de Windows — 30/10/2026

- GitHub CI #41109134435 detectó un fallo de la prueba de contención de mutex: el test reentraba desde el mismo hilo del propietario. Windows permite reentrar a un mutex desde su hilo dueño; **no** demostraba competencia real. Se corrigió para ejecutar la segunda adquisición desde otra goroutine/hilo del sistema operativo.
- La implementación del mutex ahora inmoviliza el goroutine propietario con runtime.LockOSThread hasta ReleaseMutex y usa sync.Once para cerrar el handle una sola vez. Esta exigencia es crítica porque el mutex de Windows pertenece al hilo, no al proceso Go.
- Para verificar que un mutex abandonado realmente se recupera, el test conserva un handle de kernel en el padre mientras el hijo termina abruptamente; así no se confunde el rescate de un objeto abandonado con crear un objeto nuevo.
- El restaurador de tarea CI usa ahora el mutex nativo antes de leer journal/restaurar y rechaza de entrada la tarea VOLVE-DNS-SERVER-0270. Este cambio es exclusivamente de laboratorio y no habilita producción.
- CI definitivo pendiente: https://github.com/apdocentepba-hub/volve-updates/actions/runs/41109704800. **No** acreditar puntos adicionales antes del resultado verde 3/3.
- Todavía faltan una ACL propia para el objeto mutex de producción, un SYSTEM watchdog registrado con disparador de inicio, recuperación efectiva y prueba de reinicio persistente en la misma VM. Por seguridad **no** aplicar este mutex experimental a la tarea real.


## Avance: auditoría independiente de decisión de rescate al arrancar (30/10/2026)

- Se agregó el ejecutable watchdog con opción `--audit-resident-boot-plan <INSTALL-ROOT>`. La función `auditResidentBootPlan` devuelve `recover-original` únicamente cuando existe un journal `recovery-required` y se verifica la cadena completa de original instalado, respaldo NTFS, tarea SYSTEM y journal; si hay un recibo terminal auténtico, devuelve `no-action`. La operación es exclusivamente de lectura.
- Pruebas Windows: crean respaldo y journal descartables, ejecutan el comando desde un proceso distinto, comprueban pendiente/confirmado, rechazo de EXE adulterado y journal roto. **No se modifican tareas SYSTEM ni red**, y no simulan un reboot real.
- Se corrigió el test de catálogo DNS en Windows que falló en #41109879360 al elegir 32 puertos TCP temporales no válidos para UDP en el runner. Ahora elige un puerto UDP temporal primero, comprueba TCP en ese mismo puerto y reintenta hasta 128 veces; el test no fue omitido ni se alteró el DNS real. Evidencia pendiente de CI de la corrección.
- Ejecución con el nuevo auditor: https://github.com/apdocentepba-hub/volve-updates/actions/runs/41110541483. Al registrar este avance, Windows y Linux estaban en progreso; no se declaró aprobado el nuevo código.
- Marcadores: paso 2 **40%** y paso 3 **30%** hasta que exista nueva evidencia integral. Lo siguiente prioritario es instalar y verificar un watchdog SYSTEM genuino sobre una VM persistente, con exclusión de procesos y restauración de tarea+motor limitada y autorizada. La tarea productiva continúa bloqueada.


## Avance de auditoría de arranque: corrección de Windows y pruebas adversas (30/10/2026)

- GitHub Actions #41110661239, #41110541483 y #41110512059 identificaron un problema de compilación limitado al nuevo auditor independiente: importación `motorupdate` no utilizada después de copiarlo al paquete watchdog. Causa confirmada en logs `windows-build`. Se eliminó con commit `ff4b809e73f2`.
- El nuevo `auditResidentBootPlan` sigue siendo **solo lectura** y se limita a estados journal auténticos: pendiente → recuperar original (únicamente tras verificar la cadena completa); confirmado/restaurado → no intervenir. No ejecuta rollback ni modifica el DNS productivo.
- Tests adicionales commit `2f0b812d88e1`: rechazar el XML de la tarea SYSTEM adulterado y un `resident-result.json` con `committed` falso o no ligado a la intención original.
- Última validación CI de código nuevo: https://github.com/apdocentepba-hub/volve-updates/actions/runs/41111279348. Al registrar esta entrada está **queued**, sin resultado aprobado; la compilación corregida anterior https://github.com/apdocentepba-hub/volve-updates/actions/runs/41110975418 está **in_progress**.
- Afirmaciones permitidas: código subido y causa del fallo anterior verificada. Afirmaciones NO permitidas: watchdog productivo funcionando, restauración real después de un reinicio, actualización automática instalada en 0.28.6, o CI nuevo aprobado antes de completarse.
- Porcentajes verificados **sin cambios**: paso 2 **40%** y paso 3 **30%**. Siguiente bloqueo prioritario: controlador SYSTEM persistente con rollback real, acompañado por prueba de misma VM Windows tras reinicio y firma editorial legítima.


## Avance comprobado — Primer motor real bajo SYSTEM con DNS/53 y consulta externa (30/10/2026)

**GitHub Actions [#41124486390](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41124486390): trabajo Windows fresh-system-dns53 COMPLETADO CON ÉXITO.** La ejecución reconstruyó el código completo por SHA-256, compiló una variante aislada de VOLVÉ con etiqueta `volveci`, creó una tarea **descartable** de Windows bajo el usuario SYSTEM, inició **el runner productivo de DNS** en 127.0.0.1:53 y [::1]:53, y efectuó consultas UDP desde **otro proceso**. Las pruebas comprobaron bloqueos NXDOMAIN de `betwarrior.bet.ar`, `www.betwarrior.bet.ar` y `stake.com`, además de un dominio permitido, propiedad exclusiva de los endpoints por el proceso SYSTEM y preservación del DNS del sistema y `hosts`. Al terminar se retiró la tarea descartable.

**Código:** `inapp/ci_fresh_dns53_windows.go`, `inapp/ci_fresh_dns53_windows_test.go` y flujo `.github/workflows/volve-0287-fresh-system-dns53.yml`. Estos archivos CI NO se compilan en releases normales sin la etiqueta especial, y la tarea de prueba no usa `VOLVE-DNS-SERVER-0270`.

**Crédito de progreso:** el subentregable de ensayos de DNS/identidad/rollback pasa de 12/15 a **15/15**, elevando el paso 2 a **43/100**. Sigue abierto: driver de instalación permanente, firma editorial de la release, watchdog SYSTEM persistente, cambio transaccional de DNS del adaptador con reversión, actualización desde el programa instalado y **reinicio real de VM persistente**. Este CI NO es un instalador descargable ni demuestra protección sostenida en la PC del usuario. **Paso 3 permanece 30/100**.
