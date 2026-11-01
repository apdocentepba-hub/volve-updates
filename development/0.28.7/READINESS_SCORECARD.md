# VOLVÉ 0.28.7 — Scorecard de actualización SIN reinstalar

Última revisión: 2026-10-31. Rama de laboratorio: `feature/motor-updater-0287-pilot`.

**Progreso de ingeniería del piloto: 50% (5/10 puertas de aceptación aprobadas).**
Escala interna de 10 hitos de peso igual; se acredita 10% solamente cuando las pruebas delimitadas del hito aprobaron. Los hitos pendientes pueden tener código parcial. **No** equivale a 50% de confiabilidad, probabilidad de lanzamiento ni permiso para instalar en producción.

| Puerta | Criterio de aceptación | Estado | Crédito |
| --- | --- | --- | ---: |
| 1 | CI de compilación, pruebas Linux/Windows y rollback del piloto | Aprobado; run 41251480434 | 10% |
| 2 | DNS real IPv4/IPv6 en puerto 53 con catálogo de laboratorio, en VM efímera | Aprobado; run 41049825576 | 10% |
| 3 | Tarea temporal SYSTEM, candidato firmado en laboratorio y watchdog independiente en el mismo arranque | Aprobado; run 41057083973 | 10% |
| 4 | Inventarios Windows de tareas y servicios de solo lectura, clasificación conservadora con regresiones | Aprobado; runs 41251480487 y 41252704303 | 10% |
| 5 | Inventario completo e integrado de archivos instalados, servicios, tareas, DNS, listeners/53 y recuperación | Aprobado SOLO como inventario read-only en VM Windows; CI #41257655408 | 10% |
| 6 | Identidad y permiso de migración del motor heredado realmente instalado, firmados por editor legítimo | En curso: 2/4 subcontroles de laboratorio aprobados; adaptador nativo read-only CI #41260532066. Pendientes PC real y permiso editorial auténtico | 0% |
| 7 | Controlador de conmutación productivo protegido con backups, ACL, journal y watchdog independiente | Pendiente; **prohibido cambiar VOLVE-DNS-SERVER-0270** | 0% |
| 8 | VM Windows persistente: conmutar, reiniciar de verdad, verificar servicio DNS y rollback con evidencia auditable | Pendiente; no confundir simulaciones con reinicios reales | 0% |
| 9 | Publicación oficial firmada y Centro compatible con instalación desde programa existente | Pendiente; sin claves privadas en repositorio | 0% |
| 10 | Ensayo integral de migración 0.28.6 -> nueva versión, salud y recuperación, antes de autorización de despliegue | Pendiente; la PC del usuario permanece intacta | 0% |

## Cambio de esta etapa

Nuevos archivos: `inapp/fresh_service_inventory_windows.go`,
`inapp/fresh_service_inventory_windows_test.go`,
`.github/workflows/volve-0287-fresh-service-inventory-readonly.yml`.

La prueba #41252704303 aprobó en Windows real alojado por GitHub.
Detecta servicios vinculados por nombre, nombre visible o ruta de ejecución;
incluye servicios detenidos y renombrados. Rechaza JSON inválido, incompleto,
duplicado, ajeno o sobredimensionado. Es **solo inspección**: no altera servicios,
tareas, DNS, archivos ni registro.

## Avance adicional comprobado — 31/10/2026

**Puerta 5: 100% de sus subcomprobaciones (6 de 6), aprobado como preflight de laboratorio de solo lectura.**
El progreso general aumenta a **50% (5 de 10 puertas aprobadas)**. La integración productiva sigue bloqueada.

- **Permiso elevado real:** lectura del token de Windows, sin ejecutar cambios.
- **Task Scheduler y servicios Win32:** inventarios independientes, incluidas tareas o servicios anteriores/detenidos/renombrados y rechazo de evidencia ambigua.
- **DNS IPv4/IPv6:** lectura de todas las familias y adaptadores; detecta loopback 127.0.0.0/8, ::1 y IPv4-mapeadas en IPv6; rechaza registros corruptos, repetidos o con familia incorrecta.
- **Integración:** `inapp/fresh_partial_host_probe_windows.go` combina las tres observaciones y **no marca como inspeccionados** los archivos, listeners/53 ni el estado de recuperación. Es un diagnóstico parcial de solo lectura, no un instalador ni una autorización.

**Evidencia real:** [CI de DNS Windows #41253934948](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41253934948) aprobada; [CI de inventario combinado #41254025714](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41254025714) aprobada. En la VM Windows se consultaron un token administrador, cero tareas VOLVÉ, cero servicios VOLVÉ y seis registros DNS. Los escenarios ficticios prueban detección de motores anteriores, DNS locales, permisos insuficientes y respuestas falsificadas.

**Límite de las pruebas:** se consulta el Windows efímero de GitHub, no el Windows del usuario; sin bloqueo transaccional conjunto ni ejecución sobre la instalación del usuario, el estado no autoriza instalar o conmutar motores.

### Continuación: inventario de archivos y puerto DNS 53

- **Archivos del motor (4/6):** `fresh_motor_file_inventory_windows.go` comprueba una raíz instalada existente y confiable sin modificarla; identifica el motor heredado `VOLVE_DNS_Server_0270.exe`, archivos versionados y el directorio `installed-engines`. Calcula SHA-256 de ejecutables detectados pero **no** infiere una versión firmada ni autoriza instalar. Se agregaron pruebas de rutas no canónicas, archivos no regulares, nombres de motores vacíos y ausencia de la raíz.
- **Puerto 53 (5/6):** `fresh_port53_inventory_windows.go` consulta las conexiones TCP en escucha y los endpoints UDP, identifica ocupación IPv4/IPv6 y considera conservadoramente una dirección IPv6 comodín como potencialmente dual-stack. La política rechaza tanto ocupación TCP como UDP.
- **Integración:** `fresh_host_port53_integration_windows.go` conserva las cinco observaciones y obliga a que `InspectedRecoveryState=false`. El diagnóstico nunca concede instalación sin evidencia independiente de recuperación.

**Pruebas verificadas:** [archivos #41255196849](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41255196849) y [conjunto 5/6 #41255427504](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41255427504), aprobadas en Windows. En el runner efímero, la prueba nativa encontró UDP/53 IPv4 = 1 y TCP/53 IPv4 = 1, y rechazó que eso pueda pasar como puerto libre.

**Cierre de laboratorio de la puerta 5:** el sexto observador verifica el respaldo original, las ACL protegidas y los journals del motor residente. Rechaza archivos huérfanos, directorios de recuperación inesperados y respaldos con DACL modificada. **La relectura bajo mutex privilegiado y el ensayo sobre la instalación real pertenecen a las puertas 7 y 10; no están aprobadas.**


## Cierre del diagnóstico integrado 6/6 — 31/10/2026

**Código nuevo real:** `fresh_recovery_inventory_windows.go`, `fresh_recovery_inventory_windows_test.go`, `fresh_complete_host_probe_windows.go` y `fresh_complete_host_probe_windows_test.go`. `apply_overlay.go` se corrigió porque la compilación general no incluía todos los inventarios recientes.

**Control de integridad:** se inspeccionan `legacy-engine-recovery/original-before-upgrade` y `legacy-engine-recovery/motor-recovery-transaction`. El directorio de recuperación, aun vacío o con resultado `committed`/`restored`, excluye la clasificación de instalación nueva. El journal se valida con el parser estricto existente; el respaldo exige huellas de EXE y XML, y sus tres archivos tienen comprobación independiente de DACL/propietario SYSTEM o Administradores.

**Prueba aprobada:** [GitHub Actions #41257655408](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41257655408), en Windows alojado por GitHub y con el proyecto completo reconstruido desde su ZIP con SHA-256 fijado. Incluye observación real de 6/6 categorías en Windows, intentos pendientes, recibos finales, recibos huérfanos, ACL inseguras, archivos adicionales y motor protegido. En la máquina virtual se contaron 0 tareas VOLVÉ, 0 servicios VOLVÉ, pero un proceso TCP/53 IPv4 y uno UDP/53 IPv4, por lo que **esa máquina NO fue declarada apta para una instalación limpia**.

**Alcance:** el 100% de esta puerta corresponde únicamente al contrato de inventarios y sus ensayos de laboratorio; no implica una actualización ya aplicable. No se verificó la raíz real del usuario ni se obtuvo el permiso firmado de producción. La prueba de CI general completa, separada de esta validación específica, debe consultarse por su conclusión definitiva.

## Restricciones de seguridad

- 0.28.7 todavía **NO** está listo para instalar sobre la PC del usuario.
- La firma de CI no es una autorización de publicación del editor.
- Ningún test aislado autoriza desactivar o cambiar la tarea DNS productiva.
- Para el hito 5 deben obtenerse las seis observaciones desde Windows, con
  identidad privilegiada comprobada y evidencia vinculada; no marcar flags a mano.
- El progreso sólo aumenta con aceptación comprobada; la fecha no agrega progreso.


## Avance verificado del hito 6 — 01/11/2026 (sin crédito global adicional)

El informe de la PC del usuario ya acreditó los bytes y SHA-256 del motor 0.28.6 en ejecución, la huella de su tarea SYSTEM y los sockets DNS IPv4/IPv6. Se resolvió el falso rechazo por las comillas exteriores de la ruta. **No es una aprobación para migrar**.

Se implementó el enlace de revisión `legacy_observed_candidate_review.go`, que compara un informe **no confiable** con un candidato de actualización firmado, comprueba versión y compatibilidad, y rechaza datos manipulados. [CI Windows/Linux #41269240819](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41269240819) aprobada. Es una etapa de ingeniería de la puerta 6 y no un instalador; todavía se necesitan candidato firmado oficial, permiso firmado de editor, respaldo NTFS protegido y recuperación real.

**Crédito global inalterado: 50% = 5/10 puertas completas.** La puerta 6 permanece pendiente aunque sus comprobaciones parciales de identidad y vinculación ya existen. No se tocó la PC del usuario ni se publicaron sus huellas en GitHub.


## Avance del hito 7, verificado el 01/11/2026 — archivo original + tarea SYSTEM real en VM

**CI Windows #41272656067: SUCCESS**. En una VM Windows alojada por GitHub, el controlador de laboratorio restauró el ejecutable original faltante desde un respaldo íntegro, después restauró realmente una tarea SYSTEM descartable mediante XML y comprobó que su acción `--dns-service` apuntaba al ejecutable recuperado. Los tests también demostraron que no se sobrescribe un ejecutable diferente, no se permite el nombre de tarea productiva y no se escribe un recibo `restored` sin comprobar el DNS. Se corrigió el fallo de codificación XML Task Scheduler (`0x8004131a`) demostrado en el primer CI fallido #41272316133.

**Limitaciones:** motor inerte en prueba de tarea, no DNS servido ni cambios en adaptadores. El controlador de laboratorio no constituye un restorer productivo ni puede migrar 0.28.6; faltan firma auténtica de editor, conmutación completa, watchdog independiente aplicado al caso y reinicio de una VM persistente con comprobación DNS real. La prueba de DNS real SYSTEM en VM descartable existente pertenece a otra batería y **no** demuestra aún que el DNS funcione después de esta recuperación conjunta.

**Progreso global permanece 50% (5/10 hitos):** el hito 7 acumula subpruebas completadas pero su criterio íntegro aún no está aprobado. Próxima acción útil: ejecutar recuperación conjunta usando un motor DNS que responda efectivamente por IPv4/IPv6, y luego un reinicio real persistente. No solicitar otro diagnóstico a la PC del usuario para este subpaso.


## Ensayo integrado del 01/11/2026 — archivo + tarea SYSTEM + DNS/53 real de laboratorio

**Ejecutado en Windows GitHub CI #41304036745, `SUCCESS`.** Por primera vez el mismo ensayo reconstruyó el ejecutable original ausente desde un respaldo NTFS protegido, reimportó efectivamente la tarea SYSTEM de laboratorio, la inició y comprobó respuestas UDP/53 por IPv4/IPv6 de ese mismo proceso. Las reglas del motor *mínimo de prueba* respondieron NXDOMAIN para `stake.com` y `betwarrior.bet.ar`, y NOERROR para `example.org`. El registro continuó pendiente hasta verificar el resto de condiciones de recuperación.

**Alcance de la prueba:** NO es el motor real VOLVÉ ni una validación de su catálogo o actualizaciones. Tampoco es una VM persistente tras reiniciar; el resultado no equivale a una migración productiva segura. La general de Windows falló en #41272847247 por dependencia intermitente de `Get-FileHash`; se corrigió mediante SHA-256 .NET y la específica #41303405918 pasó. Debe verificarse por separado la conclusión de una corrida general no cancelada del código final.

**Estado de aceptación mantenido: 50% global, 5/10 hitos.** Hitos 6, 7, 8, 9, 10 abiertos. Próximas pruebas con prioridad: usar el motor VOLVÉ real de CI en recuperación, reanudar watchdog independiente tras verdadero reinicio, completar firma editorial original y finalmente migración 0.28.6 en PC real con autorización, respaldo y reversión.


## Ensayo conjunto con motor VOLVÉ completo — 01/11/2026

**Evidencia definitiva: [GitHub Actions #41306065399](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41306065399), Windows hosted, SUCCESS.** El mismo ensayo de recuperación reconstruyó el ejecutable original desde el respaldo protegido, restauró realmente su tarea SYSTEM descartable y **ejecutó un binario completo de VOLVÉ**, compilado con el motor DNS productivo pero un adaptador de argumentos exclusivo de CI. Cargó el catálogo determinista de **400.002 reglas** mediante el cargador real, y comprobó consultas por UDP/53 en IPv4 e IPv6: bloqueo de `stake.com` y `betwarrior.bet.ar` y resolución de prueba para `example.org`. Verificó además propietario SYSTEM del proceso y de ambos sockets; el journal de recuperación **permaneció pendiente**, sin acreditarse salud productiva o transacción final.

La primera corrida integral [#41305829291](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41305829291) alcanzó los controles positivos, pero falló en la limpieza: `Stop-Process` encontraba un PID terminado naturalmente después de la enumeración. El arreglo valida de nuevo que el PID siga correspondiendo a nuestro ejecutable, tolera que haya salido entre observaciones y exige que **no quede ningún proceso de esa ruta**. La repetición completa #41306065399 aprobó tanto el caso mínimo anterior como el caso de motor real, incluida la limpieza. El adaptador `ci_post_switch_real_motor_shim_windows.go` se inyecta únicamente durante esa prueba, **no** se integra en el programa distribuible mediante `apply_overlay.go`.

**Alcance estricto:** VM efímera, motor real con catálogo *de laboratorio*, tarea `VOLVE-CI-*`, sin tocar DNS de adaptadores, `hosts`, Centro instalado ni tarea productiva `VOLVE-DNS-SERVER-0270`. No se ha probado un reinicio auténtico de la **misma VM persistente**, un watchdog de producción, una firma editorial auténtica ni una actualización de 0.28.6 en una PC de usuario. **Progreso global: 50% (5/10 puertas aprobadas)**. Hitos 6–10 abiertos.


## 01/11/2026 — Preparación operativa del motor FULL para reinicio REAL de VM

**Resultado aprobado: [CI Windows #41307605114](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41307605114), SUCCESS**. La prueba compiló el **motor VOLVÉ completo** en variante `volveci` desde el ZIP de código con SHA-256 fijado, preparó un directorio restringido, generó el catálogo determinista Full de 400.005 registros mediante el propio ejecutable, registró una tarea real SYSTEM con disparador AtStartup en VM descartable, la inició y verificó seis consultas DNS reales (IPv4/IPv6; dos dominios bloqueados + uno permitido por familia). Detuvo y retiró la tarea, verificó que no quedaran procesos propios y que no cambiaran el DNS de adaptadores ni el archivo `hosts`.

**Control de falsos positivos:** al invocar `Verify` sin reiniciar Windows, el sistema **rechazó** la evidencia. El contrato de eventos [#41307118907](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41307118907) aprobó en Windows con 17 pruebas adversariales. El verificador de motor en funcionamiento requiere una misma instancia 118/100/200 posterior al arranque real, tarea y proceso SYSTEM, puertos DNS/53 del mismo PID, SHA-256 de motor y catálogo intactos, y ventana temporal de hasta 30 minutos. El protocolo y los límites están documentados en [lab/VM_FULL_DNS_REBOOT.md](lab/VM_FULL_DNS_REBOOT.md).

**Defectos encontrados y corregidos**: el runner no tenía habilitado el historial Task Scheduler, y el primer arranque del motor rechazaba una carpeta de kit protegida preexistente sin el catálogo. El workflow ahora habilita ese historial solo en la VM efímera y restaura su estado. El ejecutable `volveci` incorpora la orden única `--ci-prepare-full-catalog` para crear el Full determinista antes de registrar la tarea SYSTEM, sin abrir DNS/53; el modo `--ci-boot-dns53` se limita a 30 minutos. No se altera el comportamiento del binario de distribución, que no incluye la etiqueta `volveci`.

**NO CERTIFICADO**: la máquina Windows de CI **no se reinició**. Una VM real persistente todavía debe producir su `boot-dns-after.json` después de un reinicio auténtico. Tampoco existe firma editorial auténtica, watchdog productivo ni migración 0.28.6->0.28.7 verificada de punta a punta. **Hito 8 permanece pendiente, progreso global 50% (5/10).** No instalar en la computadora del usuario, no publicar motor estable ni activar actualizaciones automáticas.


## 01/11/2026 — Corrección real del bloqueo de rescate tras un cambio de motor

**CI dedicada aprobada: [#41308531736](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41308531736), Ubuntu y Windows SUCCESS.** También aprobó la prueba previa de auditoría [#41308386981](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41308386981). Hasta ahora el clasificador de arranque `auditResidentBootPlan` y el controlador independiente de laboratorio `residentCIBootDriver` aún llamaban al comprobador **preconmutación** `auditPendingResidentChain`; este exigía que el ejecutable anterior continuara instalado. Una actualización interrumpida podía dejar ese archivo ausente o reemplazado, por lo que el propio rescatador no obtenía una decisión de recuperación aunque el respaldo protegido fuese válido.

**REALIZADO:** el clasificador posterior al cambio ahora lee `auditPostSwitchResidentRecovery`, que verifica respaldo original NTFS, XML, SHA-256 y journal pendiente **sin depender del motor activo**. El adaptador de rescate CI usa la misma prueba y, bajo el mismo mutex exclusivo que mantiene `RecoverPendingResidentAfterBoot`, puede reconstruir realmente el ejecutable original faltante desde el respaldo protegido antes de reimportar la tarea SYSTEM descartable. Se evita volver a adquirir ese mutex (bloqueo recursivo) y nunca se permite sobrescribir un ejecutable distinto sin una transacción adicional. El test de cambio durante DNS comprueba la protección del **respaldo**, no la mera presencia del antiguo ejecutable en vivo.

**COMPROBADO EN WINDOWS:** `TestIndependentBootAuditPlansRecoveryAfterOldMotorDisappearsOrIsReplaced` aprobó los casos ausente, sobrescrito e intacto; `TestIndependentBootAuditRejectsTamperedProtectedBackupAfterLiveMotorMissing` rechazó respaldo EXE, XML y recibo alterados. `TestResidentCIBootDriverRebuildsMissingExeBeforeTaskRecovery` demostró recuperación física en disco de los bytes del ejecutable, invocación de importación de tarea simulada mediante ejecutor inyectado, y recibo de recuperación solo tras comprobaciones de salud del test. `TestResidentCIBootDriverRejectsBackupDriftDuringDNSProbe` también aprobó. Los tests no tocan la tarea productiva.

**LÍMITES:** el driver de este ensayo solo admite tareas `VOLVE-CI-*` en CI; su ejecutor de Task Scheduler es inyectado en esta batería, por lo que esta evidencia **no** acredita una restauración autónoma en el equipo del usuario ni una reinstalación/actualización de 0.28.6. La recuperación conjunta con una tarea SYSTEM real y DNS productivo ya tiene otro ensayo específico aprobado (#41306065399), pero falta conectar todo en un watchdog productivo con permiso editorial legítimo y superar un **reinicio real de VM persistente**. Nada fue publicado ni instalado.

**Aceptación sin cambios: 50% (5 de 10 hitos).** La puerta 7 progresa, pero aún no cumple sus criterios productivos completos. El próximo hito concreto es un controlador independiente de recuperación productiva, con permiso firmado, protección de identidad y restitución verificable después de reiniciar realmente Windows.


## 01/11/2026 — Recuperación de candidato reemplazado, con Scheduler SYSTEM real

**Aprobado: [GitHub Actions #41310602984](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41310602984), Windows SUCCESS.** Se extendió el recuperador restringido de CI: cuando el antiguo ejecutable sigue ocupado por un archivo diferente, solo admite sustitución si sus bytes coinciden con **el SHA-256 exacto del candidato registrado en el journal protegido**. Si el archivo no coincide, es un vínculo, está fuera de los límites o la instantánea del original falla, la recuperación se niega. El original se copia a un archivo de preparación y se sincroniza antes de efectuar el reemplazo de laboratorio; el mismo respaldo y journal se verifican otra vez justo antes de la operación y se verifica el SHA-256 resultante.

**Evidencia práctica:** la prueba `TestPostSwitchSystemTaskCILabRestoresRealDisposableSystemTaskAndOriginalBytes` pasó ambos escenarios `missing` y `journal-pinned-replacement` en una VM Windows alojada por GitHub: reconstruyó los bytes originales y restauró una **tarea temporal SYSTEM auténtica** mediante el Programador de tareas. El test adicional `TestPostSwitchSystemTaskCILabFailsBeforeSchedulerWhenOriginalIsDifferent` confirmó el rechazo de un archivo desconocido. El journal siguió pendiente: restauración de archivo/tarea **no** significa DNS o conectividad saludable ni un resultado final autorizado.

**Separación obligatoria:** el candidato firmado mencionado en el fixture son bytes sintéticos cuyo SHA-256 está vinculado al journal; no hay comprobación de una firma real del editor. Todo está confinado a nombres `VOLVE-CI-*`, runner GitHub hosted y ruta temporal. No se tocó VOLVÉ 0.28.6 del usuario. El test adicional de bloqueo de archivo abierto se agregó en commit `2fc3f59c` y requiere su propio resultado verde; no se infiere de la prueba previa.

**Sigue abierto:** permiso editorial auténtico, exclusivo/handles seguros en el controlador productivo, watchdog firmado e independiente que sobreviva reinicio real, salud DNS+Internet de producción, integración desde el botón instalado y migración final. El progreso global permanece **50% (5/10 puertas)**.


## 01/11/2026 — Rescate desde un proceso Windows independiente (CI)

**COMPROBADO: [GitHub Actions #41331212545](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41331212545), Windows hosted SUCCESS.** Se corrigió el test `TestPostSwitchSystemTaskCILabRestoresRealDisposableSystemTaskAndOriginalBytes` para lanzar un proceso Windows realmente distinto de su proceso padre, pasando exclusivamente una raíz de laboratorio temporal y un nombre de tarea `VOLVE-CI-ManagedMotor-*`. El hijo vuelve a verificar respaldo NTFS, SHA-256 y journal pendiente, obtiene el mutex global, restituye físicamente el ejecutable original y reimporta una tarea real SYSTEM descartable. El padre valida posteriormente los archivos y la tarea Windows. En ambos escenarios **`missing` y `journal-pinned-replacement` el test pasó**; el journal permaneció `recovery-required` porque aún no se certificó la salud productiva de DNS y conexión.

**Alcance:** proceso independiente real pero sin reinicio de Windows y sin que el padre necesariamente termine; no hay arranque automático del watchdog en el boot, ni firma editorial productiva. La restauración usa nombres y ejecutables de laboratorio, nunca `VOLVE-DNS-SERVER-0270`. Es un **subcontrol completado** del diseño de la puerta 7, no la puerta 7 completa. No hubo modificación del equipo del usuario, DNS de adaptadores o canal de publicación.

**Progreso global sin cambio: 50% (5 de 10 hitos).** El experimento específico de recuperación independiente pasó **2/2 escenarios (100% del ensayo)**, pero las puertas 6–10 no reciben crédito hasta alcanzar sus criterios completos. La batería general posterior al nuevo commit se comprueba por separado y no se presume aprobada.



## 01/11/2026 — Verificación real DNS53 + SYSTEM + conectividad antes del recibo

**Evidencia: GitHub Actions Windows #41337942228 y #41338153644, ambas SUCCESS.**
Se introdujo un comprobador acotado a la VM de GitHub `resident_real_completion_ci_windows_test.go`, incluido por el overlay de compilación pero nunca enlazado a un controlador de producción.

El test recupera el ejecutable original desde el respaldo NTFS, restaura una tarea SYSTEM descartable, arranca el **motor VOLVÉ real** con catálogo de laboratorio de más de 400.000 reglas y verifica respuestas UDP/53 IPv4+IPv6 de dominios bloqueados y permitidos. El resultado final de recuperación se publica únicamente tras comprobar dos veces: ejecutable con SHA-256 original coincidente con journal, tarea Scheduler SYSTEM con acción/argumentos exactos, proceso con SID `S-1-5-18`, titularidad PID de ambos sockets UDP/53; y realizar además consultas DNS efectivas y una prueba de conectividad TCP directa a IP pública (no se confunde con navegación HTTP/HTTPS completa).

**Prueba negativa nueva, también aprobada (#41338153644):** se inyecta una falla de conectividad EXTERNA después de verificar identidad real SYSTEM y DNS real. `ConfirmResidentRecoveryOutcome` rechaza finalizar, mantiene el journal `recovery-required` y no genera recibo. Luego, sin usar respuestas ficticias para Internet, el ensayo vuelve a realizar pruebas reales y publica un único recibo `restored`. Un segundo intento de cerrar el mismo journal se rechaza.

**Límites:** aunque la recuperación usa un proceso y una tarea SYSTEM reales en Windows, **no** demuestra comportamiento tras reinicio real, no implementa watchdog productivo persistente, no habilita cambios en la tarea instalada ni valida un permiso firmado del editor destinado a usuarios. El resto de los controles completos de las puertas 6–10 continúa pendiente. No se publicaron binarios ni se tocó VOLVÉ 0.28.6.

**Porcentajes:** ensayo específico (incluida prueba de falla): **100% aprobado**; aceptación global de producto **50% (5/10 puertas)** sin cambio.


## 01/11/2026 — Idempotencia ante interrupción tras restaurar SYSTEM

**Comprobado:** [Windows GitHub Actions #41338763565](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41338763565), `success`. Se resolvió un estado de recuperación pendiente que antes quedaba bloqueado: la tarea descartable SYSTEM ya había sido restaurada a su ejecutable/argumentos originales, pero un corte ocurrió antes del recibo terminal. El nuevo verificador de `resident_pilot_restore_windows.go` acepta **solo la acción original exacta** o la acción candidata exacta, y vuelve a verificar el SHA-256 del ejecutable y XML protegidos ANTES de decidir si importa la tarea. Si la acción original ya está colocada, devuelve éxito técnico sin una segunda importación; el journal sigue pendiente hasta las verificaciones independientes de identidad/DNS/conectividad.

**Prueba real:** para `missing` y `journal-pinned-replacement`, la VM Windows creó una tarea SYSTEM temporal, ejecutó la restauración mediante un proceso distinto y, con la tarea ya correcta, efectuó un **segundo proceso de recuperación**. Ambos escenarios pasaron, conservando tarea original, bytes originales y journal `recovery-required`. No hubo cambios de DNS ni de la tarea productiva.

**Negativo adicional aprobado:** [Windows GitHub Actions #41339026567](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41339026567), `success`. En los dos escenarios se cambiaron deliberadamente los argumentos de la tarea SYSTEM descartable a `--wrong-untrusted-arguments`; un nuevo proceso independiente **rechazó** la recuperación, dejó sin modificar la tarea adulterada y conservó `recovery-required`. La regresión demuestra que la idempotencia no autoriza sobrescribir estados desconocidos. No se cambió la tarea productiva ni se publicó un instalador.

**Progreso de aceptación global: 50% (5/10 hitos).** Es subcontrol CI de la puerta 7; aún falta watchdog productivo firmado y persistente, reinicio REAL de VM, permiso editorial auténtico y migración 0.28.6 → 0.28.7.


## 01/11/2026 — Watchdog EXE separado, tarea SYSTEM AtStartup manual, sin reinicio

**Evidencia completa:**
- [GitHub Actions #41339731482](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41339731482) y [#41339885900](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41339885900), ambas `SUCCESS`: se compiló un **EXE de watchdog independiente** distinto del ejecutable de `go test`, se ejerció su CLI restringida `--recover-resident-ci-task` en una VM Windows hospedada por GitHub y recuperó físicamente el original en escenarios `missing` y `journal-pinned-replacement`. Reintento idempotente, argumento adulterado rechazado, tarea productiva prohibida y ejecución self-hosted rechazada.
- [GitHub Actions #41342083997](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41342083997), `SUCCESS`: una tarea de Programador de tareas auténtica, principal `S-1-5-18` (SYSTEM) y disparador **AtStartup**, lanzó manualmente un bootstrap PowerShell **EXCLUSIVO DEL LABORATORIO**, que a su vez ejecutó el EXE independiente como SYSTEM. La tarea recuperó los bytes originales de su respaldo NTFS y la acción exacta de otra tarea SYSTEM temporal; Task Scheduler informó finalización sin error; el journal permaneció `recovery-required`, sin recibo terminal.
- Los intentos fallidos [#41340213914](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41340213914), [#41340804532](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41340804532) y [#41341725819](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41341725819) **no se ocultan**. En el último, el diagnóstico informó SID SYSTEM `S-1-5-18`, código `1` y rechazo explícito `CI recovery root outside the disposable temp hierarchy`. La corrección no desactivó ese límite: cambió la ubicación de la fixture a `Windows\\SystemTemp`, ubicación del servicio SYSTEM, y el siguiente ensayo fue verde.

**Límites de aceptación:** el disparador AtStartup fue **registrado pero ejecutado manualmente**; el sistema operativo NO se reinició. No se comprobó el reinicio real de una VM persistente. El arranque usó un bootstrap de entorno solo CI, no un servicio/autoinicio productivo instalado. La tarea real `VOLVE-DNS-SERVER-0270`, el DNS de adaptadores, el motor 0.28.6 del usuario y la publicación siguieron intactos. Los bytes sintéticos con SHA-256 en el journal no constituyen una firma legítima del editor.

**Porcentajes:** subensayo AtStartup SYSTEM ejecutado manualmente **100% aprobado**. **Progreso global permanece 50% (5/10 puertas)**; faltan autorización editorial auténtica, watchdog productivo y prueba tras reinicio real de VM persistente, publicación firmada y transición completa 0.28.6→0.28.7.


## 01/11/2026 — Puerta 6: borrador de permiso editorial sin claves privadas

**Evidencia:** [GitHub Actions #41342896493](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41342896493), **Ubuntu SUCCESS y Windows SUCCESS**, código de rama `feature/motor-updater-0287-pilot`.

**Realizado:** se agregó `motorupdate.PrepareLegacyMigrationDraftReadOnly` y `DraftPermitBytesReadOnly`, archivos `inapp/legacy_migration_draft.go` y `inapp/legacy_migration_draft_test.go`. El procedimiento reconstruye el paquete editorial desde el **respaldo original protegido**, **dos preflights vivos** de motor/tarea/DNS e **identidad del candidato verificada con la clave pública de releases existente**. Rechaza cambios de respaldo, bytes antiguos y candidato, claves públicas ajenas, permisos débiles, panel incompatible y reloj falso. El borrador tiene vigencia propuesta de **24 horas**, SHA-256 reproducible de JSON canónico y huella de su paquete editorial. Se prueban intentos de cambiar huellas, tamaños, versión, editor y flags de autorización. Un borrador sin firma no pasa `VerifySignedUnversionedLegacyMigration`.

**Separación de seguridad:** ningún paso accede a la clave privada editorial, genera una nueva identidad de editor, publica releases, modifica DNS/tareas, cambia el programa instalado o autoriza la transición. La prueba de interoperabilidad utiliza una clave Ed25519 **efímera de CI**; no constituye una firma legítima de producción. Los detalles de la PC del usuario no se cargaron al repositorio.

**Límites de la puerta 6:** no hay un `VOLVE_DNS_Motor_0_28_7.exe` oficialmente publicado con la firma Ed25519 original ni un permiso editorial real emitido para su identidad instalada; las firmas de laboratorio no sustituyen ese requisito. La puerta 6 continúa **sin aprobar**, **0% de crédito**. Aceptación global sigue **50% (5/10 puertas)**. El borrador acelera una revisión firmada cuando existan release y aprobación reales.


## 01/11/2026 — Doble relectura editorial y rollback por cambio de SYSTEM/DNS

**Comprobado en pruebas específicas:**
- [CI #41343408532](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41343408532): **Windows SUCCESS / Ubuntu SUCCESS**. El verificador `VerifySignedUnversionedLegacyMigration` ahora realiza **dos inspecciones de SYSTEM y DNS por cada prueba de permiso**, comparando el motor instalado (SHA-256 y tamaño), respaldo protegido, manifest firmado, vigencia del permiso y ausencia de registro de instalación administrada antes de devolver una prueba válida. Los ensayos negativos sustituyen estos elementos durante la segunda inspección y exigen rechazo. El permiso firmado de CI usa una clave efímera; **no** existe aún firma oficial para la PC.
- [CI #41343572083](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41343572083): **Windows SUCCESS / Ubuntu SUCCESS**. Se agregó `TestSignedLegacyTransactionRestoresIfLiveSYSTEMChangesAtSecondProof`: durante el segundo permiso, tanto la primera como la segunda relectura de SYSTEM/DNS deben impedir el `Switch` y `Commit` y obligar a la ruta de recuperación con sondas de DNS/conectividad. El contrato ahora exige **4 comprobaciones vivas de SYSTEM/DNS y 2 del watchdog** en una transacción exitosa de laboratorio. El test antiguo se actualizó para imponer más controles, sin suprimir protección.
- La batería general del commit `57c90ce` comenzó en [#41343572090](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41343572090). En la última comprobación disponible estaban aprobados Linux y reversión; Windows seguía ejecutándose. No se presume conclusión verde antes de verificarla.

**Limitación crítica:** las relecturas reducen condiciones de carrera pero no sustituyen un mutex de sistema operativo que cubra la transición real. La interfaz `SignedLegacySwitchDriver` todavía carece de implementación productiva certificada. Falta una **clave editorial auténtica**, un candidato firmado oficial y una prueba de recuperación después de reiniciar realmente Windows; por lo tanto **puertas 6 y 7 siguen abiertas, progreso global 50% (5/10)**. Ningún test modificó la instalación real o el DNS del usuario.


## 01/11/2026 — Barrera posterior a DNS y mutex real de laboratorio

**Barrera después de DNS en puerta 7 — comprobada:** [CI #41344524597](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41344524597), **Windows/Ubuntu SUCCESS**. `ApplySignedLegacyWithRollback` ahora revalida **después** de las pruebas DNS IPv4/IPv6 y conectividad externa, inmediatamente antes de `Commit`: (1) original protegido exacto, (2) manifest y bytes del candidato firmados, (3) copia instalada mediante `VerifyPreparedTarget`, (4) disponibilidad del watchdog independiente, (5) vigencia y firma del permiso editorial. Se agregaron pruebas que alteran esos elementos tras la salud DNS. El recibo de éxito nunca se escribe si falla alguna. Si el respaldo fue adulterado, el sistema **no lo usa para restaurar** y reporta estado CRÍTICO en vez de afirmar que se recuperó.

**Contrato de exclusión completa — comprobado en lógica y laboratorio:** `SignedLegacySwitchDriver` exige `AcquireExclusiveMigration(ctx)` **antes de cualquier inspección**, conserva la liberación durante toda la transacción (firma, preflight, respaldo, instalación candidata, cambio de tarea, DNS, Internet, confirmación y rollback ante error) y la libera al salir. Los tests rechazan bloqueo ocupado, función `release` nula y cancelación; comprueban el bloqueo durante la reversión. [CI #41344812137](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41344812137), Windows/Ubuntu SUCCESS para los casos del controlador de laboratorio.

**Kernel mutex Windows REAL — comprobado:** `motorupdate.AcquireWindowsSignedLegacyLabLease` se limita a tareas con nombre `VOLVE-CI-ManagedMotor-<nonce>` y a runners GitHub Windows hosted; deriva `Global\\VOLVE-CI-DNSLock-<nonce>`, reutilizando el mutex nativo de Windows de la batería de recuperación DNS. El test usa concurrencia real entre goroutines/hilos Windows y confirma que el segundo dueño no ingresa mientras la primera operación conserva el mutex; luego confirma que el recurso se reutiliza tras liberarse. Rechaza la tarea productiva y runners no autorizados. [CI #41345315437](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41345315437), **SUCCESS, ambos tests realmente ejecutados, go vet aprobado**.

**LÍMITE SIN ATENUANTES:** el mutex kernel probado **no** está instalado ni registrado en la PC real y el watchdog de laboratorio distinto todavía no ha demostrado tomar esa MISMA identidad de mutex. El nuevo contrato aún carece de implementación productiva protegida y con editor autenticado. Tampoco hubo reboot verdadero de VM persistente ni publicación oficial 0.28.7. Por lo tanto **la puerta 7 NO está aprobada**; global **50% = 5/10 puertas completas**. La batería general de este cambio debe comprobarse por separado y no se presume verde sin conclusión del job Windows.


## 01/11/2026 — Exclusión REAL de mutex entre dos procesos Windows

**Aprobado:** [CI Windows #41345570973](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41345570973), `SUCCESS`. Además de la prueba anterior entre hilos, se agregó `TestSignedLegacyLabKernelMutexCrossProcessExclusion`: el primer proceso conserva `Global\\VOLVE-CI-DNSLock-<nonce>`; otro **proceso EXE de pruebas independiente** intenta tomar ese mismo mutex con un timeout de 400 ms y **debe recibir context.DeadlineExceeded**; después, el dueño lo libera y el proceso independiente debe adquirirlo y liberarlo correctamente. El test ejecutó realmente ambos procesos. En la batería dedicada también aprobaron el rechazo de tareas productivas, de nombre ajeno y runner no autorizado; `go vet` aprobado. Ninguna tarea de Windows, DNS o servicio productivo fue alterado.

**Estado honesto del hito:** existe una primitiva **Windows real** de exclusión entre procesos y el contrato de transacción obliga a mantenerla durante rollback; sin embargo, **el watchdog de rescate real aún NO comparte el mismo mutex**, no hay controlador productivo certificado ni reinicio de VM persistente. La prueba entre procesos acredita la primitiva **solo del laboratorio**. Global **50% (5/10 puertas)**; hito 7 permanece abierto.

**Batería general:** la ejecución del código de los cambios más recientes se seguirá desde GitHub Actions; las corridas canceladas por commits posteriores NO cuentan como éxitos. Se necesita una corrida final Windows completa antes de considerar estable la integración.


## 01/11/2026 — Verificación DNS local en Windows del usuario (solo lectura)

**Origen de la evidencia:** informe entregado voluntariamente por el usuario `VOLVE_DNS53_LEGIBLE_20261101_173700.json` y ZIP equivalente, inspeccionados en sesión. Los archivos son **privados del equipo y NO fueron incorporados al repositorio**; esta nota resume únicamente verificaciones no identificantes.

**COMPROBADO EN LA PC REAL, SIN ALTERAR INSTALACIÓN:**
- Tarea original encontrada, principal `SYSTEM`, acción/argumentos de servicio DNS coincidentes; un único proceso del motor en ejecución bajo `SYSTEM`.
- El proceso inspeccionado era titular de los endpoints UDP/53 y TCP/53 observados.
- **12/12 consultas DNS locales** respondieron por los servidores loopback IPv4 (`127.0.0.1`) e IPv6 (`::1`). Las 8 consultas A/AAAA a **dos dominios de apuestas del ensayo** devolvieron `NXDOMAIN` con 0 respuestas; las 4 consultas A/AAAA del dominio permitido devolvieron `NOERROR` con respuestas.
- El ZIP contenía exactamente el JSON de lectura; no había duplicados ni huecos entre las 12 combinaciones servidor/dominio/tipo.

**NO SE HA COMPROBADO:** que el tráfico de todos los navegadores atraviese VOLVÉ, resistencia a DNS-over-HTTPS/VPN/evasión, cobertura integral del catálogo, conectividad externa, recuperación después de un reinicio real ni versión firmada del motor heredado. Tampoco se comprobó que el watchdog productivo y el actualizador compartan mutex y proceso independiente.

**IMPACTO EN LA PLANIFICACIÓN:** el bloqueo DNS de **0.28.6 está activo para los casos consultados**; se descarta como prioridad cambiarlo solo para repetir pruebas funcionales básicas. Esta evidencia ayuda a identificar el estado inicial para un ensayo posterior, pero NO acredita las firmas auténticas ni autoriza cambiar `VOLVE-DNS-SERVER-0270`. **Progreso 50% (5/10 hitos), hitos 6–10 sin aprobación.**


## 01/11/2026 — Vía rápida: bloqueo compartido actualizador y watchdog

**Cambio de arquitectura y objetivo:** el `SignedLegacySwitchDriver` de CI adquiría `Global\\VOLVE-CI-DNSLock-<nonce>`, pero el watchdog independiente adquiría `Global\\VOLVE-CI-BootLock-<nonce>`. Dos mutexes distintos no protegen la misma operación. Ahora el coordinador de migración firmado utiliza **exactamente el BootLock del watchdog**. El proceso de rescate `--recover-pilot-journal` vuelve a leer y valida el journal *bajo el mismo mutex*, antes de cualquier acceso privilegiado al Programador de tareas. El productor del rollback entrega el bloqueo solo con el journal temporal en estado `pending`, antes de arrancar y esperar al watchdog SYSTEM, evitando una espera circular. Este **handoff** está restringido al test de Windows con tareas `VOLVE-CI-ManagedMotor-*`; no se modifica la tarea productiva ni los DNS del usuario.

**Regresión detectada y corregida:** la primera implementación permitía erróneamente nombres `BootLock` por el helper API tradicionalmente restringido a `DNSLock`. Se restauró la validación estricta de esa API, separando la ruta autorizada del editor de laboratorio. [GitHub Actions #41348522765](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41348522765) **Windows/Ubuntu SUCCESS** en el contrato de recuperación; [#41348522721](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41348522721) **Windows SUCCESS** para el mutex de migración. Los casos de nombre inválido, productor distinto y cancelación deben seguir rechazándose.

**CI corta dedicada:** [#41348569828](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41348569828) reconstruye las fuentes verificadas, compila el watchdog como .exe independiente, prueba que no puede superar el BootLock retenido y ejecuta la migración firmada de laboratorio con recuperación por tarea SYSTEM real. **RESULTADO COMPROBADO: SUCCESS (Windows CI #41348569828).** El watchdog independiente fue compilado como .exe nuevo. El test `TestIndependentWatchdogUsesMigrationBootLockEvenForTerminalJournal` pasó. El ensayo `TestWindowsSignedUnversionedMigrationWithActualSYSTEMRecovery` pasó ambos escenarios reales de tarea SYSTEM **signed-commit (20,95 s)** y **SYSTEM-watchdog-rollback-on-connectivity-failure (23,06 s)**. El journal final fue `committed` en el caso normal y `restored` después de falla de conectividad. **Este es un subcontrol integrado de la puerta 7, no su aprobación productiva**: tareas VOLVE-CI temporales, firma efímera de laboratorio y sin reinicio real ni cambios de DNS de la PC del usuario. La primera versión del ensayo falló por un import ausente y fue corregida antes de esta ejecución verde.

**Alcance y condiciones de aceptación pendientes:** el contrato productivo necesita mutex con ACL SYS/Administradores, activación del watchdog fuera del proceso actualizador, journal duradero, exclusión de carreras durante el handoff, recuperación completa de ejecutable y tarea DNS, pruebas reales posteriores a reinicio, firma editorial auténtica y migración final del Centro instalado. **Progreso 50% = 5/10 puertas**. Es código y ensayos de integración, no una actualización liberada.


## 01/11/2026 — Handoff de mutex + recuperación + segundo bloqueo de verificaciones

**Código corregido:** `development/0.28.7/inapp/signed_legacy_windows_task_lab_test.go` implementa ahora una cesión y **re-adquisición del mismo `Global\\VOLVE-CI-BootLock-<nonce>`** durante rollback con watchdog SYSTEM independiente. Antes, tras el journal `restored`, el proceso actualizador leía la tarea SYSTEM y hacía sus probes finales sin mantener el mutex: la tarea podía cambiar entre la restauración y la certificación. El controlador CI ahora (1) exige journal `pending` vinculado antes de liberar el mutex, (2) arranca y espera el watchdog SYSTEM desde un proceso independiente, (3) ante el journal `restored` **vuelve a adquirir el mutex** con contexto acotado, (4) vuelve a leer y validar el journal bajo bloqueo, (5) realiza probes locales y de conectividad solo mientras conserva el bloqueo, (6) libera **el segundo lease** mediante la clausura final del contrato transaccional. Al fallar la re-adquisición no reporta recuperación segura. Nada de esto habilita el driver productivo.

**Evidencia reproducible:** [GitHub Actions Windows #41349248684](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41349248684), **SUCCESS**; `TestIndependentWatchdogUsesMigrationBootLockEvenForTerminalJournal` pasó; `TestWindowsSignedUnversionedMigrationWithActualSYSTEMRecovery` pasó los dos caminos `signed-commit` (**committed**) y `SYSTEM-watchdog-rollback-on-connectivity-failure` (**restored**). En ambos el test comprueba que no queda un lease colgado y que se puede reacquirir el BootLock después de salir. El caso `Probe/ProbeConnectivity` falla si no se recuperó el mutex. El watchdog se compiló separadamente; se usó tarea SYSTEM real descartable en Windows hosted CI con firma efímera. Esta prueba **no** hace verdadero reinicio, no prueba el motor productivo y no escribe tarea/DNS de la PC del usuario.

**No cambiar porcentaje:** 50% = 5/10 puertas. Hitos 6 (firma auténtica), 7 (driver productivo + journal/ACL/watchdog protegido), 8 (reinicio real persistente), 9 (publicación + Centro instalado), 10 (ensayo final 0.28.6→0.28.7) continúan pendientes. La batería general #41349248618 había aprobado Linux y rollback de Scheduler, pero Windows seguía en el test largo del watchdog: el resultado de la prueba focal no se debe extrapolar a toda esa batería.


## 01/11/2026 — Mutex nativo protegido para el controlador productivo de Windows

**Cambio de código comprobado:** el archivo `development/0.28.7/inapp/resident_transition_lock_windows.go` incorpora `motorupdate.AcquireProtectedResidentTransitionLease(ctx)`, una **primitiva Win32 real** para el futuro actualizador y recuperador productivos. No modifica la tarea DNS, ni instala, ni desinstala nada. En lugar de aceptar un nombre arbitrario o un mutex `VOLVE-CI-*`, usa la **identidad fija** `Global\\VOLVE-ResidentMotor-Transition`. Se permite adquirirlo solo bajo un token elevado de Administradores o SYSTEM, con un objeto Win32 creado mediante SDDL protegido de propietario Administradores y DACL exclusiva SYSTEM/Administradores. Se vuelve a leer el descriptor de seguridad **incluso si el objeto ya existía**, y se rechaza si dueño, derechos o ACE no coinciden con la política estricta. El dueño del mutex se fija al hilo del sistema operativo; se espera de manera cancelable y se libera de forma idempotente. `WAIT_ABANDONED` habilita que el recuperador tome la exclusión tras la muerte del actualizador, **sin declarar éxito de la migración**. El componente entró en el overlay autenticado de compilación general.

**Prueba real de Windows:** [GitHub Actions #41350216432](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41350216432), **SUCCESS**. `go test` y `go vet` aprobaron, con pruebas:
- `TestProtectedResidentTransitionMutexCrossProcessAndExactACL`: dos **procesos Windows independientes**, exclusión durante titularidad y nueva adquisición al liberar.
- `TestProtectedResidentMutexRejectsUnsafePreexistingObject`: objeto ya existente con descriptor inseguro es **rechazado**, sin usar el mutex falso.
- `TestProtectedResidentMutexCancelledBeforeObjectAcquisition`: cancelación no adquiere nada.
- `TestProtectedResidentMutexRecoversAfterOwnerProcessDies`: proceso dueño termina abruptamente sin ejecutar release; un segundo proceso vuelve a adquirir el **mismo objeto aún existente**, tratando correctamente el abandono.

Los tests se ejecutaron **solo en Windows hosted CI**, con una VM descartable y sin escribir tareas, DNS ni motor. La función hija usada por `exec` apareció como SKIP en la ejecución padre, pero **sí se ejecutó en los procesos hijos** dentro de ambas pruebas padre, las cuales aprobaron.

**Límites y aceptación:** producción todavía no invoca esta primitiva desde `SignedLegacySwitchDriver` ni desde un watchdog productivo verificado, y no existe una liberación autenticada con permiso editorial legítimo. La primitiva se ha comprobado, **NO** una transacción completa productiva. Hito 7 sigue abierto y **progreso general 50% = 5/10 puertas**. Próximos trabajos: integrar ambos extremos en la misma identidad de mutex protegida, persistir journal y respaldo con ACL, enlazar firma editorial auténtica y recuperación tras reinicio real de VM persistente.


**Compatibilidad futura:** la identidad productiva del mutex es **estable entre versiones** (`Global\\VOLVE-ResidentMotor-Transition`), deliberadamente sin sufijo 0.28.7; cualquier actualizador o watchdog futuro deberá usarla sin variaciones. El cambio de nombre se validará con la batería dedicada [#41350410798](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41350410798); no se debe considerar aprobado hasta que concluya verde.


## 01/11/2026 — Adaptadores productivos unidos por mutex protegido y handoff explícito

**IMPLEMENTADO** en `motorupdate` (Go/Windows):
- `resident_protected_boot_driver_windows.go`: `NewProtectedResidentBootDriver(operations)` obliga a que `RecoverPendingResidentAfterBoot` use `AcquireProtectedResidentTransitionLease(ctx)` y no el mutex opcional/CI del driver inyectado; la implementación real de restauración sigue pendiente.
- `resident_protected_signed_switch_windows.go`: `NewProtectedSignedLegacySwitchDriver(operations)` obliga a que la migración firmada use el **mismo mutex protegido con identidad estable entre versiones**, y exige que el delegado implemente `ProtectedSignedRecoveryHandoff`. El adaptador no activa producción y rechaza implementaciones sin protocolo de entrega al watchdog.
- En rollback, `Restore` libera el mutex *antes* de invocar `RestoreAfterProtectedHandoff(ctx)`, espera al watchdog independiente y vuelve a tomar el mutex con el contexto acotado antes de admitir pruebas de DNS local y conexión externa. Una reacquisición fallida reporta estado crítico, no recuperación certificada. La función de liberación final usa el segundo lease, evitando que el primero se cierre dos veces y el nuevo quede bloqueado.
- `watchdogcmd/resident_boot_protected_gate_windows.go` y el CLI `--audit-resident-boot-plan`: el propio ejecutable independiente debe tomar el mutex productivo **antes** de leer el journal, para no clasificar una conmutación que continúa en curso. Es diagnóstico read-only, no una ruta de mutación productiva.
- Los archivos se incorporaron al ensamblado de fuentes verificadas en `inapp/apply_overlay.go`. Los tests usan tareas temporales y VM Windows CI; ninguna ruta de producción fue modificada.

**EVIDENCIA FINALIZADA:** [CI Windows #41352149359](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41352149359), **SUCCESS**: pasaron `TestProtectedSignedSwitchAndBootRecoveryShareProductionMutex`, `TestProtectedAdaptersFailClosedWithoutTrustedOperations`, `TestIndependentBootAuditAcrossFreshProcesses`, `TestProtectedBootPlanAuditWaitsForProductionUpdateMutex`, `TestProtectedResidentBootPolicyUsesProductionMutexBeforeReadingJournal` y ambos caminos de la tarea SYSTEM de laboratorio (commit/rollback).
**Último caso adicional:** pruebas `TestProtectedSignedRollbackHandsOffThenReacquiresBeforeHealth` y `TestProtectedSignedDriverRejectsHandoffMissing` incorporadas y seleccionadas expresamente en [CI Windows #41352402296](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41352402296). **Verificar la conclusión final antes de acreditar esa nueva cobertura.**

**Pendiente:** driver Windows de conmutación productiva con respaldos durables y restaurador SYSTEM firmado; recuperación tras reinicio real de una misma VM persistente; clave y permiso editorial legítimos, paquete distribuible e integración efectiva con el Centro instalado 0.28.6. **Crédito global inalterado 50% (5/10 puertas)**. Los adaptadores no son por sí mismos una migración de un equipo real.


## 01/11/2026 — Recuperación vinculada a la firma editorial real, no solo hashes locales

**Realizado en la rama (sin instalar ni modificar DNS productivo):**
- `motorupdate.VerifyResidentPublisherRecoveryBinding` comprueba en una única operación read-only la **firma Ed25519 editorial** del permiso de migración, el journal de recuperación **pendiente** con nonce y hashes exactos, y el respaldo original NTFS validado independientemente (ejecutable, XML de tarea SYSTEM y recibo). Relee journal y respaldo al final para rechazar cambios entre comprobaciones. El camino no permite una ruta distinta a `legacy-engine-recovery/original-before-upgrade` y el journal hermano `motor-recovery-transaction`.
- Los permisos vencidos **no** pueden autorizar una actualización nueva (regla original intacta), pero su firma válida **sí** puede permitir recuperar el original de una transacción pendiente que ya había sido autorizada y que sobrevivió al vencimiento. Se siguen rechazando permisos emitidos en el futuro o con vigencia excesiva.
- `NewPublisherBoundProtectedResidentBootDriver` integra esa verificación en un **adaptador Windows** con el mutex SYSTEM/Admin protegido: verifica la cadena editorial antes de `VerifySealedOriginal` y antes de `RestoreOriginal`, y coteja el journal con la intención del llamador. Realiza copias defensivas de clave pública y firma para impedir cambios silenciosos tras construirlo. **No incluye ni ejecuta todavía el restaurador productivo de archivos/tarea.**

**Evidencia reproducible:** [GitHub Actions Windows #41353286836](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41353286836) **SUCCESS**: `TestSignedPublisherBootRecoveryAcceptsExpiredPermitButNeverNewMigration`, 14 pruebas de rechazo `TestSignedPublisherBootRecoveryRejectsForgedOrUnboundEvidence/*` y prueba de callbacks de ACL/cancelación, además de los ensayos integrados de recuperación. Esta ejecución **NO** cubre el adaptador productivo nuevo agregado posteriormente.
**Batería de adaptador específico aprobada:** [GitHub Actions #41353508474](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41353508474), **SUCCESS Windows hosted CI**. Pasaron `TestPublisherBoundProtectedBootRejectsForgedGrantBeforeRestoringOriginal` (permiso válido pero vencido, firma falsa, respaldo faltante, intención distinta), `TestPublisherBoundProtectedBootRequiresSignerAndCopiesGrant`, todos los negativos de la verificación editorial, la coordinación del mutex y ambos caminos reales de tareas SYSTEM temporales (commit y watchdog rollback). Los tests confirmaron que una autorización falsa **no llega** al operador del recuperador. No demuestra todavía que dicho operador productivo exista o pueda ejecutarse tras reboot.

**No se cerró un hito nuevo:** global **50% (5/10 puertas)**. Faltan clave editorial auténtica de producción, conservación segura del permiso firmado para el watchdog tras reinicio, implementación y validación del operador Windows productivo que restaure bytes/tarea, pruebas tras reboot persistente y migración final 0.28.6→0.28.7. Las claves de CI son efímeras; nunca constituyen una versión oficial.
