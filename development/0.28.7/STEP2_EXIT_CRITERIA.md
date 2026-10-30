# VOLVÉ 0.28.7 — Criterios de cierre del paso 2/8

**Objetivo del paso 2:** disponer de una ruta de migración **implementada, verificable y reversible** desde el motor DNS que acompaña al Centro 0.28.6 hasta un motor administrado actualizado, sin reinstalación. El paso 2 **no es un permiso de publicación** ni de modificación de una PC ajena. Los pasos posteriores incluyen recuperación automática completa, ensayos de protección, migración controlada y distribución estable.

## Evidencias ya presentes en el piloto

- Respaldo local del ejecutable anterior y XML SYSTEM, hash/tamaño verificables y NTFS con propietarios y DACL protegidos.
- Validación de candidato y permiso editorial con Ed25519, contra las huellas exactas del motor anterior, su tarea y el candidato nuevo. **Solo hay firmas efímeras de CI; no un permiso editorial real publicado.**
- Contrato de transacción con preflight, staging, reconfirmación, prueba DNS/Internet y rollback en contexto independiente.
- Watchdog Windows independiente: restauración comprobada con **tareas CI descartables**, no con la tarea real.
- Journal durable de dos archivos create-only con nonce y terminal hash-bound, auditado desde otro proceso.
- Auditoría read-only `--audit-resident-chain <INSTALL-ROOT>` que exige coherencia entre respaldo, journal pendiente y bytes del motor instalado; no inicia tareas ni cambia DNS. Commits piloto: `60c62eaa`, `c3875fbc`, `7f0f2c3c`, `dd46945c`, `c1f2ca9b`, `1a4e33b3`. Su aceptación depende de las pruebas del commit final, no de runs antiguos.

## Condiciones para poder marcar PASO 2 CERRADO

- [ ] **A. Identidad editorial legítima.** Obtener un permiso de migración firmado con la clave editorial correcta que corresponda al hash **real** del ejecutable heredado y al candidato verificable. Sin inventar la versión histórica del motor ni sustituir por la clave efímera de CI.
- [ ] **B. Recuperación independiente productiva.** Implementar el recuperador SYSTEM para la tarea exacta `VOLVE-DNS-SERVER-0270`, con control explícito de tarea, binario, permisos NTFS, journal protegido y recuperación si desaparece el Centro. Registrar y verificar el watchdog **antes** de cambiar la tarea. No eliminar el bloqueo productivo actual sin esta condición.
- [ ] **C. Controlador Windows de migración.** Integrar un driver real con los contratos `SignedLegacySwitchDriver` y `ManagedSwitchDriver`, bloqueos de concurrencia y pinning del candidato; firma y permisos revalidados inmediatamente antes del switch; ejecución, sondeos locales y de Internet y rollback ante fallos.
- [ ] **D. Ensayo adverso repetible.** Probar actualizaciones con interrupción/kill del actualizador, candidato corrupto, permisos alterados, tarea SYSTEM sustituida, reinicio durante el cambio y caída DNS/Internet; nunca declarar recuperado sin pruebas efectivas de DNS y conectividad.
- [ ] **E. Reinicio Windows real.** Probar en una **VM Windows persistente** la secuencia `preparar -> cambiar -> reiniciar -> detectar el journal -> recuperar o confirmar -> comprobar DNS IPv4/IPv6 puerto 53` sobre **la misma VM**, con evidencia del evento real de boot. GitHub-hosted Windows jobs no cumplen por sí solos esta condición.
- [ ] **F. Revisión y autorización de cierre.** Cero pruebas críticas rojas, auditoría de seguridad, rollback explicado y artefacto candidato trazable. Aun con paso 2 aprobado, `main`, `stable.json` y `motor-stable.json` no se publican hasta las etapas previstas de entrega.

## Bloqueo actual y siguiente acción

La **brecha principal** es B+C: todavía **no existe** el driver que efectivamente conmuta el motor real junto a un watchdog productivo capaz de revertirlo. El código incluye una barrera explícita que rechaza `VOLVE-DNS-SERVER-0270` en `switchVerifiedMotorTaskAction`. **Debe permanecer activa** hasta demostrar B, C, D y E con autorización. El siguiente desarrollo prioritario es implementar y verificar el adaptador SYSTEM watchdog y el driver **en un laboratorio aislado**, sin desproteger ni alterar el VOLVÉ 0.28.6 instalado.

**No realizado:** migración real del motor del usuario, firma editorial de producción, publicación de motor estable y prueba de reboot persistente.


## Nueva subetapa: restauración del journal residente mediante tarea CI (30/10/2026)

**Código:** el watchdog ahora incluye `resident_pilot_restore_windows.go`. Es un mecanismo de recuperación que consume el **formato residente** (respaldo del motor original + tarea SYSTEM + journal con nonce), comprueba coherencia de SHA/ACL antes de cualquier acción, y construye una restauración usando PowerShell con comprobaciones de identidad de la tarea y del motor tanto antes como después de reimportar el XML. La ruta del destino es derivada de la versión registrada; el ejecutable candidato puede estar ausente, porque un rollback debe preservar la posibilidad de restaurar cuando falla la descarga/instalación. **Barrera obligatoria:** la función rechaza `VOLVE-DNS-SERVER-0270` y cualquier nombre distinto de tareas `VOLVE-CI-ManagedMotor-*` de laboratorio. No existe opción productiva CLI para esta operación ni se registra ninguna tarea real.

**Pruebas añadidas:** `resident_pilot_restore_windows_test.go` utiliza un ejecutor PowerShell **simulado** (sin importar, crear, arrancar ni modificar ninguna tarea del Programador). Exige rechazo del nombre productivo, respaldo adulterado, journal finalizado, ausencia de ejecutor, resultados ambiguos o fallo en la restitución. Comprueba que el plan exige comprobar la identidad SYSTEM y las huellas del archivo XML/EXE antes de la importación. El circuito de restauración real del Scheduler sigue **SIN EJECUTAR** y requerirá una prueba Windows aislada expresamente habilitada.

**Trazabilidad:** commits `452a25ba`, `1714cd66`, `9b6d0e48`, `48884528`; [CI actual](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41100759300). Los resultados de CI deben consultarse antes de anunciar aprobación.

**Sigue bloqueado:** tarea SYSTEM y motor DNS productivos, journal terminal confirmado por probes DNS/Internet, permiso editorial firmado de producción, prueba de reinicio real en VM persistente, y publicación del motor.


## Avance adicional — validación de ACL y confirmación con DNS (30/10/2026)

**REALIZADO:** el watchdog `checkResidentJournalNTFS` pasó de aceptar cualquier ACE permitida de SYSTEM/Administradores a exigir explícitamente `FullControl` para ambos en cada entrada del journal. Caso negativo `TestWindowsResidentJournalRejectsReadOnlyAdministratorACL` evita confundir DACL protegida pero de solo lectura con journal recuperable (commits `bfbdebf339bb`, `3362501c4ca7`).

**NUEVO CONTRATO DE CIERRE:** `motorupdate.ConfirmResidentRecoveryOutcome` exige comprobar identidad efectiva de la tarea/motor SYSTEM antes y después de los sondeos, respuesta DNS local y conectividad externa **antes** de crear un recibo terminal `committed` o `restored`. Mantiene `recovery-required` si cualquiera falla. `resident_completion_test.go` contiene dobles de prueba que simulan fallas en cada compuerta y concurrencia; **no** prueban DNS real. No existe aún un adaptador Windows productivo que implemente `ResidentCompletionChecks`; por eso la nueva API no se invoca desde el Centro (commits `1a87743b0920`, `c3b2afd1334e`, `5da6977372d8`).

**CORRECCIÓN EXTRA:** en la rutina de restauración de tarea CI se calcula SHA-256 del mismo bloque de bytes XML que se transforma para la importación, evitando la comprobación seguida de una segunda lectura independiente. Esta rutina continúa restringida a tareas efímeras de prueba; sin invocación productiva ni validación de reinicio real (commit `27eb68559994`).

**CI PENDIENTE:** [Actions #41102094866](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41102094866). En el último control figuraba `queued` por espera de GitHub Actions. No presentar esta versión como compilada, ensayada o aprobada en Windows hasta recibir conclusión definitiva. La anterior [#41097414505](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41097414505) sí figura exitosa.

**BLOQUEOS NO RESUELTOS:** permisos editoriales reales, tarea SYSTEM del watchdog PRODUCTIVA y persistente, recuperación efectiva del motor/tarea, driver Windows de conmutación, sondeos reales post-cambio y prueba de reinicio de VM persistente. `VOLVE-DNS-SERVER-0270` sigue bloqueada por diseño; no modificar `main`, el canal estable ni la instalación 0.28.6.


## Avance: sondeos activos DNS/Internet y enlace al cierre de recuperación (30/10/2026)

**CÓDIGO SUBIDO:** `resident_health_probe.go` implementa consultas DNS **reales** A por 127.0.0.1 y AAAA por ::1 (puertos 53 en la configuración productiva propuesta, efímeros en CI), con ID aleatorio, coincidencia de pregunta, RCODE y RR de respuesta completa; rechazo de respuestas truncadas, identificadores falsos, registros de dirección incompletos y destinos que no sean loopback. `ProbeResidentInternetAt` comprueba alcance TCP por direcciones IP sin resolver nombres; el perfil de destino propuesto usa 1.1.1.1:443 y 9.9.9.9:443. No se altera la red, se envía solo la consulta DNS necesaria.

**CI PRUEBA:** `resident_health_probe_test.go` crea servidores DNS IPv4/IPv6 y un listener TCP **descartables**, comprueba respuestas efectivas y casos adversos. `resident_active_health.go` implementa `ResidentCompletionChecks` utilizando esos sondeos activos, pero exige callback separado de identidad SYSTEM, deliberadamente **ausente del driver productivo actual**. El test integrador confirma que un journal solo termina tras pruebas reales DNS+TCP y doble chequeo de identidad simulado, y que un DNS falso deja `recovery-required`.

**EVIDENCIA LOCAL:** `go test -race -count=1 ./...`, `go vet ./...` y compilación cruzada GOOS=windows/amd64 del módulo aislado de sondeos completaron sin errores en Linux, con IPv4/IPv6 y TCP reales *de loopback*. Esto **no** es ejecución real en Windows ni prueba post-reinicio; GitHub Actions del commit integrado [#41103624036](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41103624036) estaba `queued` al registrar el avance.

**PRÓXIMO BLOQUEO TÉCNICO:** conectar `ResidentActiveHealthChecks.VerifyIdentity` a la tarea SYSTEM y al ejecutable firmado que efectivamente esté ejecutándose (no solo a la acción configurada), montar un watchdog persistente independiente con permisos restringidos, probar restauración en Windows y reinicio real sobre la misma VM. Mantener prohibido `VOLVE-DNS-SERVER-0270` hasta aprobar los criterios B-E.


## Subetapa: prueba de identidad SYSTEM y propiedad de DNS/53 (30/10/2026)

**REALIZADO EN RAMA PILOTO (SIN DESPLIEGUE):** el módulo `motorupdate/resident_running_identity.go` define evidencia estructurada de identidad del motor activo: tarea exacta `VOLVE-DNS-SERVER-0270` en raíz y estado Running, un único Exec `--dns-service`, principal SYSTEM, un único proceso con el ejecutable y línea de comandos exactos, dueño SYSTEM por SID y hash SHA-256 del EXE en disco. **Control ampliado:** el PID de ese proceso debe coincidir con el propietario de **ambos** listeners UDP `127.0.0.1:53` y `::1:53`; un proceso distinto que escuche DNS o una acción extra del Scheduler bloquea la verificación.

**OBSERVADOR WINDOWS:** `resident_running_identity_windows.go` solo consulta `Get-ScheduledTask`, `Win32_Process`, `GetOwnerSid`, `Get-NetUDPEndpoint` y `Get-FileHash`. No contiene comandos de mutación. El observador usa una única tarea literal y únicamente nombres de ejecutables esperados. Sus pruebas inyectan un resultado sintético y verifican rechazo de JSON incompleto, ruta ajena, cancelación y comando mutador en el texto.

**VINCULACIÓN AL RESPALDO:** `resident_outcome_identity_windows.go` exige respaldo protegido cuyo hash coincida con el journal; para `committed`, exige además revalidar la firma editorial del motor destino instalado, su versión y hash. Expone un adaptador de identidad de solo lectura para `NewResidentNetworkHealth`, pero **NO está invocado desde el controlador productivo**.

**EVIDENCIA DE PRUEBAS:** el validador puro de identidad fue comprobado localmente con `go test -race`, `go vet` y compilación cruzada de su módulo aislado para Windows. GitHub Actions de la rama completa sigue siendo la validación definitiva para el conjunto; ver [ejecución #41104967298](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41104967298). No afirmar que pasó hasta confirmar el estado final.

**LIMITACIONES FUNDAMENTALES:** comprobar tarea, proceso, PID y puertos es evidencia fuerte de identidad observable, pero **NO demuestra por sí solo** que Task Scheduler haya sido quien lanzó el proceso, que los bytes cargados en memoria sigan idénticos al disco, ni que exista un permiso editorial de migración vigente o un watchdog SYSTEM productivo. La ejecución real de esa comprobación sobre Windows instalado y el ensayo de reinicio persistente continúan pendientes. El bloqueo del switch productivo permanece activo y `main` no se modifica.
