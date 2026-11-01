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
