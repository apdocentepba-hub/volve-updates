# VOLVÉ 0.28.7 — Tablero de aceptación de actualización del motor Windows
Actualizado: 2026-11-02 UTC. **Rama piloto** `feature/motor-updater-0287-pilot`. Sin acceso directo al equipo del usuario.

## Progreso global verificable: 65/100 puntos (65 %)

**IMPORTANTE:** el porcentaje es un **indicador ponderado de criterios técnicos superados**, NO una medida del tiempo de desarrollo, seguridad garantizada, preparación para instalar, disponibilidad de la actualización, progreso del componente Android ni porcentaje del conjunto total del proyecto social VOLVÉ. La aptitud de **liberación del motor sigue en NO APROBADO (0 % de liberación)** mientras falte un criterio obligatorio.

| Criterio de aceptación Windows | Peso | Puntos aprobados | % de etapa | Evidencia/limitación |
| --- | ---: | ---: | ---: | --- |
| Centro 0.28.7 actualizado sin reinstalar | 12 | 12 | 100 % | Evidencia previa de launcher y captura en Windows real; Centro no implica motor nuevo |
| Motor DNS existente bloquea apuestas en Windows real | 10 | 10 | 100 % | Diagnósticos previos, bloqueo puntual y consultas IPv4/IPv6; no promete neutralizar VPN o DoH ajenos |
| Catálogo y tarea horaria | 10 | 8 | 80 % | Catálogo de 630.446 dominios y tarea `VOLVE-CATALOGO-0230` con `LastTaskResult=0`; falta prueba recurrente de descarga/cambio efectivo |
| Candidato del motor 0.28.7 firmado | 10 | 10 | 100 % | [CI #41361613951](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41361613951) autenticidad Ed25519/editor y bytes del EXE publicado; NO hay canal publicado |
| Permiso editorial + identidad del motor anterior | 10 | 8 | 80 % | Permiso firmado offline y diagnóstico histórico del motor; falta reconfirmación de identidad actual y vigencia al migrar |
| Recuperación de bytes de respaldo original con NTFS | 12 | 10 | 83 % | [CI #41367221500](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41367221500) 6/6 tests; falta envolverlo en watchdog SYSTEM real |
| Restauración firmada de tarea SYSTEM (XML + AtStartup) | 12 | 7 | 58 % | [CI #41371447005](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41371447005) y [#41371447017](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41371447017) SUCCESS; solo pruebas aisladas/CI, no restauración productiva |
| Secuencia productiva de conmutación y recuperación independiente SYSTEM | 12 | 0 | 0 % | Código de transacción piloto incorporado en [`8fc9ac8`](https://github.com/apdocentepba-hub/volve-updates/commit/8fc9ac8061dae17eafaf8caa85b9049796fe8234), **todavía sin aceptación integrada**; no consola/launcher, sin conexión con canal |
| Prueba de reinicio real, interrupción y recuperación DNS + Internet | 7 | 0 | 0 % | GitHub hosted CI no hace reboot persistente real; faltan ensayos que reanuden tras inicio de SO |
| Publicación, migración de equipo y validación final | 5 | 0 | 0 % | `releases/motor-stable.json` permanece ausente; no instalado nuevo motor en PC |
| **TOTAL** | **100** | **65** | **65 %** | **No listo para instalar el motor** |

## Último avance de ingeniería

- Commit [`8fc9ac8`](https://github.com/apdocentepba-hub/volve-updates/commit/8fc9ac8061dae17eafaf8caa85b9049796fe8234): refactoriza restaurador del ejecutable y de la tarea en variantes bajo el **mismo mutex kernel**. Nuevo coordinador `recoverSignedLegacyOriginalAndSYSTEMTaskWindows` (todavía sin entrada productiva) cubre ejecutable ausente, original intacto y rechaza ejecutable candidato/desconocido. No cierra journal sin verificar DNS.
- Prueba enfocada Windows: [#41373120038](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41373120038). **En curso al registrar esta versión del informe**. No sumar puntos al scorecard por ese commit hasta `success` en pruebas nuevas.
- Los porcentajes de cada criterio se actualizarán solamente al superar pruebas y criterios de aceptación. Si surgen regresiones, los puntos se reducen; no se extrapolan tests de VM al equipo del usuario.

## Siguientes pasos

1. Obtener resultado del test combinado Windows; corregir errores de compilación/ACL y probar rechazo por motor activo, revocación editorial y falla parcial.
2. Conectar coordinador a watchdog real que se ejecute como SYSTEM, manteniendo permiso firmado genuino, ACL y exclusión mutua, sin ejecutar migración en producción todavía.
3. Ensayar apagado/reinicio de **VM persistente**, reconstrucción de archivo/tarea y DNS53 IPv4/IPv6, navegación y rollback con fallas forzadas.
4. Solo luego preparar release de motor y autorización en el equipo, con reversión y consentimiento antes de cambiar tareas reales.

El desarrollo de Android queda **fuera de este indicador** y necesita su propia auditoría de estado; no inferir progreso de Windows.

## Control actualizado — integrador bajo un único mutex

- [CI #41373231157](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41373231157): **FAIL por timeout de 8 min** durante el grupo anterior de pruebas firmadas de tarea SYSTEM. Los trabajos Linux y Scheduler del piloto aprobaron, el Windows falló. No computar esta prueba como aceptación de la recuperación combinada.
- [`622884c`](https://github.com/apdocentepba-hub/volve-updates/commit/622884c4eaf6826ccff92fcd804b17209dfa8978): corregida una importación de `time` en un test del mutex, sin cambios en el motor en producción.
- [`edaaa7d`](https://github.com/apdocentepba-hub/volve-updates/commit/edaaa7d31f722142d1434143482c33b1901bd482): suite enfocada separada en **tres trabajos Windows independientes** (tarea original; recuperación combinada exitosa; rechazos por corrupción/port53/SYSTEM y fallo parcial). No se alteran criterios criptográficos ni permisos; cada conjunto tiene presupuesto y resultado propios.
- [CI #41374392594](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41374392594): **tres trabajos en ejecución** al registrar este control. Sólo si los tres finalizan `success`, se considerará la integración de pruebas superada. **Avance reconocido: 65/100** hasta esa evidencia.
- La funcionalidad no está conectada al watchdog SYSTEM de producción. Además, no se ha demostrado recuperación con Windows realmente reiniciado y la misma VM persistente. Ningún permiso para activar `releases/motor-stable.json`.

**Siguiente criterio bloqueante:** restaurador completo original EXE+XML+arranque DNS e informe de salud tras reinicio persistente. No confundir la aprobación de los tests unitarios con despliegue.

## 02/11/2026 01:56 UTC — Coordinador conjunto probado bajo Windows

- [`8fc9ac8`](https://github.com/apdocentepba-hub/volve-updates/commit/8fc9ac8061dae17eafaf8caa85b9049796fe8234): operación combinada de recuperación del EXE original y tarea SYSTEM bajo **una única adquisición y liberación del mutex del kernel**; las funciones internas no vuelven a adquirirlo. Sigue **sin CLI productiva**, no arranca DNS ni declara recuperación completada.
- [`272701d`](https://github.com/apdocentepba-hub/volve-updates/commit/272701dece723a09fa6365ea5eb40761752c725b): reparación del workflow y separación en tres trabajos Windows para evitar timeouts opacos. Prueba [#41374570067](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41374570067).
- Confirmado en logs: **combined-success: SUCCESS (2 de 2)**. Restituye los bytes originales + invoca importación de tarea mientras el mutex está retenido y reintenta sin reescribir un EXE que ya es correcto.
- Confirmado en logs: **combined-rejections: SUCCESS (4 de 4)**. Rechaza EXE desconocido, puerto DNS53 activo, token SYSTEM ausente/cancelación; una falla de importación deja el respaldo y journal PENDING sin registrar éxito falso.
- **task-only (regresión firmada de Scheduler): en ejecución** al momento de este registro. No registrar el workflow completo como aprobado hasta confirmación de ese tercer job.
- **Marcador general permanece 65/100.** No elevarlo por tests de CI que no constituyen una operación instalada y recuperada tras reboot persistente. Canal de motor público NO publicado.

## CI Windows definitivo del coordinador: 3 de 3 PASS

- [`272701d`](https://github.com/apdocentepba-hub/volve-updates/commit/272701dece723a09fa6365ea5eb40761752c725b) reparó la sintaxis de PowerShell del workflow dividido, que antes fallaba sin ejecutar tests.
- [CI #41374570067](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41374570067): **SUCCESS en sus tres jobs Windows**. Logs verificados:
  - **combined-success: 2/2 PASS**. Archivo faltante restituido y posterior tarea SYSTEM bajo un solo mutex; recuperación reiniciada con EXE original intacto y sin sobrescritura.
  - **combined-rejections: 4/4 PASS**. EXE desconocido, DNS53 ocupado, falla al importar tarea (journal sigue PENDING y EXE restaurado conservado), ausencia de SYSTEM o cancelación.
  - **task-only: SUCCESS**. Restauración firmada de tarea, bloqueo de XML/EXE adulterado, puerto DNS53 ocupado y administrador no SYSTEM; watchdog Windows compila.
- La batería del coordinador queda aprobada **en fixture Windows de CI, no en producción**. Se mantiene el indicador global **65/100**, dado que los puntos de integración productiva exigen un watchdog realmente instalado bajo SYSTEM, reinicio persistente, verificación DNS/Internet y liberación segura.
- Bloqueo siguiente: unir el coordinador aprobado a una identidad SYSTEM auténtica y un método de sellado DACL del nuevo EXE, y ejecutarlo con respaldo/editor real en VM persistente. Las funciones todavía son privadas/sin CLI productiva y no se publicaron.

## 02/11/2026 UTC — Validación de identidad SYSTEM real y protección DACL

- [`cde653d`](https://github.com/apdocentepba-hub/volve-updates/commit/cde653dd47c382dd8435e25615fdd8ab63f461be): adaptador **no conectado al launcher** `recoverSignedOriginalAndSYSTEMTaskWithPublisherBindingWindows` con SID Windows SYSTEM `S-1-5-18`, clave pública editorial fija, journal/backup con NTFS protegido y controles de proceso/puerto53. Nueva función `sealResidentOriginalRecoveryStageNTFS` restringe el sellado ACL del EXE temporal a SYSTEM y BUILTIN/Administrators, verificando después el descriptor. No hay publicación de motor ni CLI productiva.
- [Windows #41375853204](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41375853204) **SUCCESS: 3/3 jobs** tras compilar el adaptador y verificar rechazo de runner no SYSTEM, junto con pruebas anteriores del coordinador combinado.
- [`f759549`](https://github.com/apdocentepba-hub/volve-updates/commit/f759549f85145b16a68e1f0197a5ae1333ddc7e1): agregado ensayo más exigente en Windows desechable. Un proceso Go compilado se ejecuta mediante **tarea SYSTEM real** (sin reiniciar Windows) y debe sellar un archivo EXE sintético con DACL NTFS protegida; tarea de prueba y datos temporales se eliminan. No modifica ni instala tareas VOLVÉ productivas.
- [`1e1a225`](https://github.com/apdocentepba-hub/volve-updates/commit/1e1a22511404ba93a4514763c3c922f96242b1a9): reparación de cadena literal del regex del test en workflow; [Windows #41376176541](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41376176541) en ejecución al registrar. **No declarar aprobado el ensayo SYSTEM real sin observar PASS**.
- **65/100 mantiene su criterio**: la prueba de SYSTEM en tarea desechable no cumple por sí sola el hito de recuperación tras reboot persistente ni la actualización del motor desplegada. El canal estable del motor continúa ausente.

### Siguiente barrera
Ensayo con token SYSTEM del sellado + integración de tarea original; después verificar arranque real DNS IPv4 e IPv6 y respuesta de bloqueo, seguido de interrupción con reboot de VM persistente. Solo con esos criterios y diagnóstico actualizado del equipo se podrá autorizar un upgrade de motor por el Centro.

## 02/11/2026 UTC — Última barrera SYSTEM/NTFS: diagnóstico y corrección del ensayo

- [Windows #41376176541](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41376176541): resultado final **FAIL 1/3**. Los jobs `combined-success` y `combined-rejections` fueron **SUCCESS**. `task-only` aprobó sus tests del restaurador firmado, pero falló **antes de ejecutar el ensayo extra SYSTEM/NTFS**: el binario de pruebas recibió `-test` en lugar de argumentos completos. No es falla confirmada de la recuperación instalada.
- [`2400563`](https://github.com/apdocentepba-hub/volve-updates/commit/24005636c23115769833b7c4378ca1e9c6589d8d): intento de corrección del PowerShell. Generó un YAML incompleto por sustitución de cadena y GitHub rechazó [#41377452415](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41377452415) sin crear jobs. **No atribuirle aprobación**.
- [`795a58f`](https://github.com/apdocentepba-hub/volve-updates/commit/795a58fb27698e4fc377054c8e993c0e600c4ba9): reconstruido el bloque final de YAML sin sustituciones; argumentos individuales `'-test.run=^TestResidentCIStageSealerActualDisposableSYSTEMTask$'`, `'-test.timeout=3m'`, `'-test.v'`. GitHub aceptó el workflow [#41377525166](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41377525166) y programó los tres jobs Windows.
- En la última revisión de #41377525166: `combined-success` **SUCCESS**; `combined-rejections` y `task-only` todavía estaban en ejecución, por lo tanto **NO declarar 3/3 ni una prueba SYSTEM NTFS exitosa**.
- **65/100 puntos mantenidos**, y liberación del motor no autorizada. Centro 0.28.7 estable; canal público `releases/motor-stable.json` ausente. Ningún paso modificó la instalación del usuario.

**Próximo hito bloqueante:** que el ensayo SYSTEM/NTFS con tarea descartable realmente se ejecute y compruebe el sellado. Luego enlazar arranque/reinicio persistente con verificación de bloqueo DNS v4/v6 y conectividad; nunca inferir éxito de un solo resultado CI.

## 02/11/2026 UTC — Tarea SYSTEM real y sellado NTFS: aprobado

- La ejecución [#41376176541](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41376176541) había cerrado con **2/3 jobs SUCCESS**; `task-only` falló **después de aprobar los tests anteriores**, porque el proceso Go de ensayo recibía mal sus argumentos.
- El intento [`2400563`](https://github.com/apdocentepba-hub/volve-updates/commit/24005636c23115769833b7c4378ca1e9c6589d8d) generó un YAML malformado. Corregido reconstruyendo el bloque en [`795a58f`](https://github.com/apdocentepba-hub/volve-updates/commit/795a58fb27698e4fc377054c8e993c0e600c4ba9).
- **[Windows #41377525166](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41377525166): SUCCESS, 3/3 jobs**. `combined-success`, `combined-rejections` y `task-only` concluyeron exitosamente.
- Se verificó además dentro de `task-only`: `--- PASS: TestResidentCIStageSealerActualDisposableSYSTEMTask (4.08s)`; la prueba creó/arrancó una tarea de Windows descartable realmente ejecutada como SID SYSTEM, selló un EXE sintético en NTFS y comprobó que el archivo quedó con permisos protegidos. No modificó ninguna tarea del producto ni el DNS configurado en la PC.
- **Criterio superado:** identidad SYSTEM auténtica y sellado del archivo temporal protegido en VM Windows de CI. **No equivale** a recuperación completa después de reiniciar un Windows persistente, ni a una migración del motor desde el Centro.
- **Puntaje general inalterado: 65/100**. El hito de integración productiva y recuperación autónoma posterior a reboot continúa sin aprobar; el motor no fue publicado en `releases/motor-stable.json`.

**Siguiente prueba obligatoria:** VM Windows persistente con concesión editorial válida y protegida, proceso watchdog SYSTEM independiente, corte/reinicio y reanudación real de la transacción original EXE + Scheduler XML, arranque y verificación de bloqueo DNS IPv4/IPv6, conectividad y recibo de salud sin falsos positivos. No instalar ni sustituir el motor del usuario antes de superar esa barrera.


## 02/11/2026 10:38 UTC — Salud de Internet comprobable tras reinicio: contrato CI aprobado (sin reinicio)

- Nuevo verificador [\`vm_direct_internet_probe.ps1\`](../development/0.28.7/lab/vm_direct_internet_probe.ps1): el modo \`Verify\` del laboratorio de VM persistente requiere al menos una conexión **TCP real, directa, a IP numérica** a dos destinos alternativos (\`1.1.1.1:443\` y \`9.9.9.9:443\`). No confunde una respuesta DNS sintética con conectividad exterior, no modifica DNS/hosts/adaptadores y limita cada intento a 2,5 segundos.
- El artefacto de prueba registra \`directInternetTCPVerified\` y el destino alcanzado. **No** representa navegación HTTP, conectividad completa, seguridad del navegador, uso de IPv6 ni protección contra bypass por VPN/DoH.
- La VM conserva en su paquete prearranque el nuevo verificador junto con su SHA-256 protegido y lo revalida antes de ejecutar el modo \`Verify\`; un paquete anterior sin ese recurso **no obtiene certificación retrospectiva**.
- Tests sintéticos: una conexión positiva alternativa; rechazo de dos fallas, texto ambiguo y respuesta inexistente. Todos son locales y no abren sockets.
- [CI #41430279600](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41430279600): **SUCCESS**, PowerShell 5.1 parseó los cinco archivos del contrato; aprobaron la correlación de eventos de arranque y los tres rechazos de conectividad, y se rechazó verificar una VM no preparada. **Ningún reboot real ocurrió en esta CI**.
- **Progreso permanece 65/100**: el avance consiste en mejorar el criterio de salud que deberá verificarse durante un reboot real de VM persistente. No demuestra transición productiva ni habilita \`releases/motor-stable.json\`. El nuevo motor permanece **sin instalar en el equipo del usuario**.

**Siguiente barrera no superada:** completar una ejecución real \`Prepare → reboot del mismo Windows → Verify → Cleanup\` en VM aislada persistente, además de integrar watchdog y transacción de rollback del motor bajo permiso editorial firmado. Mientras no haya evidencia de esos eventos y salud DNS/Internet post-reboot, los puntos de integración y liberación siguen en cero.


## 02/11/2026 UTC — Handoff de recuperación firmada bajo un mutex ya adquirido

- [Commit \`457462d\`](https://github.com/apdocentepba-hub/volve-updates/commit/457462df22bbc24f8df7f2099c2ba63935f8683b): la operación de restauración firmada original EXE+SYSTEM XML separa la adquisición de mutex de la función interna \`recoverSignedLegacyOriginalAndSYSTEMTaskLockedWindows\`. Un watchdog independiente puede invocar la variante interna **solamente si ya posee** el bloqueo global; la variante autónoma sigue obteniéndolo ella misma. Ambas conservan verificaciones de SYSTEM, ACL, firma editorial, quiescencia, hashes y journal pendiente.
- [Prueba agregada \`de1bad6\`](https://github.com/apdocentepba-hub/volve-updates/commit/de1bad6b566137d3f8311b0dfadeab72b1891432): un test Windows adquiere antes el mutex y llama la ruta interna. Si la función reingresa al mutex no reentrante, el test falla por timeout. Se conserva journal PENDING; no hay constancia de DNS sano ni receipt de recuperación.
- La suite Windows enfocada fue reconstruida desde el último YAML que había aprobado, corrigiendo duplicaciones accidentales del selector PowerShell; [commit \`f637061\`](https://github.com/apdocentepba-hub/volve-updates/commit/f6370616b8e981b3125fd4951758c720873c1fec).
- **Validación todavía pendiente de resultado definitivo en esta anotación:** [Windows #41431312048](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41431312048). No declarar el test nuevo aprobado hasta comprobar los tres trabajos y su conclusión final.

**Puntuación invariable: 65/100.** La interfaz interna no constituye conexión efectiva al watchdog en el equipo, recuperación tras reboot ni habilitación del canal de motor.


### Corrección posterior del ensayo del handoff firmado

- [Windows #41431312048](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41431312048) **FAIL**: los rechazos de seguridad aprobaron, pero el nuevo test \`LockedHandoffDoesNotReacquireMutex\` agotó su plazo de 20 segundos antes de completar todas las verificaciones de autorización editorial/ACL; el journal permaneció pendiente y no se afirmó éxito. **No es aprobación del handoff**.
- [Commit \`752514b\`](https://github.com/apdocentepba-hub/volve-updates/commit/752514be4797d4197ec29c869698e75fae24475c): presupuesto de ejecución del test ampliado a 150 segundos, sin modificar el comportamiento del motor ni relajar condiciones de firma, NTFS, SYSTEM o quiescencia. [Nueva ejecución Windows #41431985874](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41431985874) fue iniciada y su veredicto deberá revisarse por separado.
- Las ejecuciones previas con ParserError en el YAML fueron corregidas desde la última versión aprobada, no representan evidencia de un fallo del motor desplegado.
- Progreso 65/100 y motor bloqueado para liberación hasta cerrar todos los criterios de aceptación.


## 02/11/2026 — El handoff bajo mutex pasó y se agregó adaptador de política

- [Windows CI #41431985874](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41431985874): **SUCCESS 3/3** (combined-success, combined-rejections, task-only). El nuevo test confirmó la recuperación firmada original EXE + tarea bajo un mutex compartido preadquirido; la batería de firma editorial/NTFS/SYSTEM y rechazos se mantuvo verde. No hay prueba de reboot.
- [Pilot completo #41431985858](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41431985858): **FAIL** por `go test -timeout 6m` del primer grupo de 4 particiones de watchdog; Linux y Scheduler pasaron. El proceso Windows seguía verificando autorizaciones/ACL cuando venció el límite. No atribuir ese resultado a un fallo demostrado del motor de usuario.
- [Commit `002ca2b`](https://github.com/apdocentepba-hub/volve-updates/commit/002ca2b5e2a7e5590fde80664a7d8763176728ac): partición completa de pruebas Windows ampliada de cuatro a ocho grupos con conteo de tests, comprobación de duplicados y cobertura de todos los tests descubiertos; presupuesto total de job ampliado, **sin omitir ni relajar pruebas**. El resultado completo actualizado aún requiere revisión.
- [Commit `b52d993`](https://github.com/apdocentepba-hub/volve-updates/commit/b52d993433742f28826ce3a81135286b81bc39df): adaptador interno `residentSignedBootOriginalOps` implementa `motorupdate.ResidentOriginalRecoveryOps` para usar la política ya existente con **un único mutex productivo propiedad del driver**. `VerifySealedOriginal` valida editor, respaldo/journal/nonce, SYSTEM y ausencia de DNS activo. `RestoreOriginal` recurre al coordinador bajo mutex, sin adquirir otro.
- [Commit `88dd706`](https://github.com/apdocentepba-hub/volve-updates/commit/88dd706c20e024faa73df69615d53129e6944134): nuevos tests Windows de contrato y recuperación bajo mutex real, incluida protección contra nonce equivocado, más validación estricta de journal pendiente sin recibo falso de salud.
- [Windows enfocada #41436571080](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41436571080): batería disparada para verificar compilación y nueva integración, **sin resultado definitivo al registrar este apartado**. No declarar aprobada la nueva conexión mientras falte veredicto.
- Ningún nuevo CLI, tarea de arranque, botón, canal público o archivo productivo modificado. Sin alteración del equipo del usuario. **Puntuación reconocida sigue en 65/100; liberación del motor 0% aprobada**.

**Bloqueo siguiente:** después de cerrar CI del adaptador y la regresión, implementar secuencia supervisada por SYSTEM real para reiniciar el motor restaurado y comprobar bloqueo DNS IPv4/IPv6 y conectividad; completar `Prepare → reboot real de VM persistente → Verify → Cleanup` antes de autorizar la instalación de motor.


### Corrección: motor original ya activo no debe impedir la auditoría firmada

- [Commit `ccbda76`](https://github.com/apdocentepba-hub/volve-updates/commit/ccbda7667b0ee20701c2b385c338d4b27ec809a9): en el nuevo adaptador de política, la verificación **de solo lectura** del respaldo/journal/publisher deja de exigir puerto DNS53 libre. Esto es necesario cuando el motor original ya funciona correctamente tras boot y la política sólo quiere verificar identidad y salud, sin restaurar.
- La ejecución **mutadora** `RestoreOriginal` continúa usando `recoverSignedLegacyOriginalAndSYSTEMTaskLockedWindows`, que exige proceso detenido, puerto53 libre, identidad SYSTEM, firma/editor, ACL y tarea exacta bajo el mismo mutex antes de modificar EXE/tarea. No se alteran esos límites.
- [Commit `1677548`](https://github.com/apdocentepba-hub/volve-updates/commit/1677548aec88e13ea0ffc27d6ca1ebc33dd27de1): nueva regresión Windows con DNS53 simulado ocupado: la auditoría firmada debe aceptar el original sano, pero cualquier restauración debe rechazar la mutación de Scheduler, manteniendo journal PENDING.
- [GitHub Actions #41436974914](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41436974914): ejecución de pruebas nuevas iniciada; **sin dictamen final al registrar**. La secuencia no hace reboot ni permite una migración real.
- **65/100** sigue siendo el porcentaje reconocido; falta integrar un SYSTEM watchdog independiente instalado, arranque DNS y verificación real de Internet después de reinicio persistente. No hay canal público de motor.


## 02/11/2026 — SYSTEM-only publisher-pinned boot driver: factory and real token tests

- **Comprobación anterior**: el [workflow focalizado #41436571080](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41436571080) terminó **SUCCESS, 3/3** y validó el adaptador con mutex compartido a nivel de laboratorio.
- [Commit `e60f58b`](https://github.com/apdocentepba-hub/volve-updates/commit/e60f58b79e8f8f386082ab2464da0a41672942a2): constructor **privado** `newPinnedResidentBootRecoveryDriverWindows`. Requiere token Windows SYSTEM verdadero, raíz absoluta canónica, clave pública editorial incluida en el binario, comprobación NTFS, protección de procesos/puerto DNS53 y `NewProtectedResidentBootDriver` con mutex kernel global. No admite clave, ejecutor ni mutex del llamador. **No instala ni activa ningún controlador de arranque**.
- [Commits `1773169` y `260d112`](https://github.com/apdocentepba-hub/volve-updates/commit/260d112ee1d09e2fbdad810f9b0fa54f38502412): regresiones negativas de token administrador interactivo, contexto cancelado, ruta relativa y no canónica; prueba real positiva añadida en [commit `799db3e`](https://github.com/apdocentepba-hub/volve-updates/commit/799db3edccf6d25faecb736233bb5d7f33e306d5), dentro de tarea desechable SYSTEM que únicamente construye el driver y sella una copia sintética, **sin restaurar/activar ningún motor**.
- El [workflow focalizado #41437860595](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41437860595) fue iniciado para validar las nuevas pruebas. **No se debe indicar aprobado hasta que los tres trabajos concluyan exitosamente**.
- La batería general previa [#41431985858](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41431985858) había agotado 6 minutos en el primer shard Windows; se fragmentó el conjunto de tests en ocho grupos, sin omisiones. Su resultado definitivo actualizado aún requiere comprobación.
- **Estado reconocido 65/100**, **liberación 0% aprobada**: la recuperación después de reinicio persistente de una VM, DNS/Internet post-boot y la atestación legítima del 0.28.6 instalado siguen pendientes. No se modificó la computadora del usuario.


## 02/11/2026 — Auditoría de reconstrucción: fuentes del watchdog omitidas

- La [CI #41437860595](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41437860595) marcó FAIL en los 3 grupos Windows por el error de compilación `undefined: newPinnedResidentBootRecoveryDriverWindows`. Causa verificada: el generador `development/0.28.7/inapp/apply_overlay.go` copiaba un manifiesto explícito de fuentes y **omitía cuatro archivos nuevos** (`resident_signed_boot_policy_adapter_windows.go`, su test, `resident_pinned_boot_driver_windows.go`, su test). Por tanto, las CI verdes previas **NO habían compilado ni probado el adaptador recién añadido**; sólo verificaban las rutas anteriores. Se corrige expresamente esa interpretación.
- [Commit `8edf89e`](https://github.com/apdocentepba-hub/volve-updates/commit/8edf89eaad439d9afeb96842f5051059b8c72914): incorporados los cuatro archivos al manifiesto; añadida revisión exhaustiva de los `.go` ubicados en `inapp/watchdogcmd` para fallar si cualquier fuente se omitió del árbol reconstruido. **Excepción documentada:** `ci_post_switch_real_motor_shim_windows.go`, incorporado únicamente por el laboratorio desechable específico.
- [Windows focalizada #41438183017](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41438183017): nueva ejecución iniciada desde el commit corregido. La fase Go había llegado a ejecutar tests (compilación ya no cortó al mismo punto) en la inspección realizada, **sin resultado final**.
- El estado del usuario sigue **0.28.6 instalada, actualización de motor 0.28.7 no liberada ni aplicada**, progreso técnico reconocido 65/100. Esta corrección mejora la cobertura de pruebas, pero no es certificación de un reboot real ni de un watchdog productivo.


## 02/11/2026 — Política de recuperación firmada de punta a punta (simulada)

- [Windows real #41438183017](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41438183017): **SUCCESS, 3/3**. Confirmó el adaptador firmado y constructor SYSTEM después de corregir el manifiesto de reconstrucción de fuentes; los archivos nuevos SÍ se compilaron y ejecutaron en la batería.
- [CI Windows #41438182846](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41438182846) y [#41438182840](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41438182840): **SUCCESS** para mutex y tarea SYSTEM de laboratorio y DNS53 con motor en VM efímera, respectivamente. **No se reinició una VM persistente**.
- [Commit `3e6175b`](https://github.com/apdocentepba-hub/volve-updates/commit/3e6175b799db62e6ea7dab15dd59653d15dfc261): agregada la prueba `TestSignedBootPolicyFullRecoveryUnderSharedMutexSealsExactlyOnce` para ejecutar la política COMPLETA `RecoverPendingResidentAfterBoot` con autorización Ed25519 desechable, ACL NTFS real, mutex global Windows, reimportación de tarea simulada, validaciones simuladas de identidad/DNS/Internet, recibo terminal protegido y segundo arranque idempotente sin repetición de importación. El ejecutor Scheduler, comprobaciones de identidad post-restore y sondas DNS/Internet son simulados en esta prueba; **no representa una recuperación verdadera de DNS ni reinicio de Windows**.
- [CI focalizada #41439126627](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41439126627): ejecución programada para validar la nueva prueba; **no hay aprobación registrada hasta que concluya**.
- **Bloqueo conocido de producción:** el controlador firmado rechaza de forma deliberada reemplazar un ejecutable existente con identidad de candidato exacto `exact-pinned-target-still-present`; se requiere una transición atómica y segura, con evidencia de editor y rollback, para resolver la actualización interrumpida. No relajar el rechazo a un ejecutable desconocido ni habilitar migración antes de ese criterio.
- **Bloqueo post-boot:** una tarea restaurada y firmada no es equivalente a un motor DNS corriendo; falta el controlador instalado que active/atestigüe identidad SYSTEM, DNS IPv4/IPv6 real y conectividad directa antes de escribir recibo `restored`.
- **65/100** de progreso técnico reconocido; **0% aprobación de publicación de motor**. Máquina del usuario intacta.
