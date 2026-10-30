# VOLVÉ 0.28.7 — Actualización desde el programa instalado (candidato, NO release)

**Objetivo pedido:** desde el botón nativo **Actualizar VOLVÉ**, sin desinstalación ni necesidad de buscar manualmente otro instalador.

## Qué hace este piloto

1. El botón invoca `--check-all-updates`, que conserva por compatibilidad el comando original `--check-app-updates`.
2. Consulta en paralelo dos canales independientes firmados con Ed25519: `releases/stable.json` para el Centro y `releases/motor-stable.json` para el motor DNS.
3. El Centro conserva su flujo conocido: descarga comprobada con SHA-256, marcador `VOLVE_STAGE_READY` y consentimiento UAC para que **el ejecutable instalado actual**, no el recién descargado, realice la instalación versionada del Centro.
4. Un motor DNS firmado se descarga al caché por usuario únicamente si el Centro cumple la versión mínima firmada. Se verifican firma del manifiesto, nombre, origen, tamaño y SHA-256; si ya está preparado, se verifican los bytes nuevamente.
5. **No se asume la versión del motor heredado ni se intenta actualizar el motor vivo**. El paquete preparado NO se ejecuta y no se cambian DNS, tareas SYSTEM, respaldos ni firewall. Cuando el canal del motor aún no existe, se informa sin romper la actualización del Centro.
6. La comprobación de ambos canales se ejecuta en paralelo para respetar la espera actual de 120 segundos del botón.

## Integración reproducible

El código fuente Windows de referencia de 0.28.7 se reconstruye a partir de diez partes en `complete-source-parts/` y los overlays de recuperación existentes, todos con sus SHA-256 verificados en CI.

El archivo `apply_overlay.go` copia `inapp_motor_update_windows.go` y las pruebas, y conecta dos puntos precisos del GUI y del CLI del Centro. Si el código base cambia, **rechaza** aplicar un parche que no encuentre exactamente una coincidencia. El mismo overlay se usa en los jobs de Linux y Windows de `volve-motor-0287-pilot.yml`.

El código no se copia a `main`, no altera el manifiesto firmado ni el ZIP estable, y **no es un instalador**. Hasta generar un EXE completo firmado y distribuir una nueva versión de Centro en el canal estable, la 0.28.6 instalada seguirá usando su botón original.

## Contrato de instalación y reversión de motor incorporado en el piloto

El nuevo `motorupdate.ApplyManagedWithRollback` exige que el futuro controlador de Windows:
- valide la identidad, versión y firma del candidato antes de actuar;
- confirme un respaldo duradero antes de instalar o conmutar;
- instale el nuevo ejecutable en una ubicación versionada;
- compruebe **por separado** el DNS local y la conectividad externa;
- registre la versión como confirmada **solo cuando ambas comprobaciones resulten correctas**;
- ante cualquier error posterior al respaldo, intente recuperar y comprobar el motor anterior con un contexto independiente del proceso de actualización.

Incluye pruebas de orden correcto, candidato adulterado, versión heredada no identificada, errores en cada fase y cancelación que no debe cancelar el rollback. Es un **contrato con controladores simulados**, no un controlador real de Windows; por tanto no habilita todavía el botón para reemplazar el motor en una PC.

## Windows Task Scheduler: integración del controlador de laboratorio

Se añadió `managed_windows_task_lab_test.go`, una prueba Windows que ejercita `motorupdate.ApplyManagedWithRollback` contra una tarea **SYSTEM real pero temporal e inocua** (`VOLVE-CI-ManagedMotor-<id>`):

- Guarda y sincroniza a disco el XML original del Programador de tareas con SHA-256.
- Copia el candidato **de prueba** firmado con clave efímera a una ruta versionada y modifica únicamente la acción de esa tarea desechable.
- En el caso nominal confirma la operación solo después de las verificaciones; en una falla simulada de conectividad, restaura la acción original y comprueba la recuperación.
- En ambos casos elimina la tarea de laboratorio sin tocar tareas de producción ni puertos, adaptadores o parámetros DNS.

**GitHub Actions aprobado:** [ejecución 40982068789](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40982068789) (Windows, Linux, recuperación en laboratorio). La primera ejecución de este ensayo identificó un problema real de `FlushFileBuffers` al abrir el respaldo en modo lectura; se corrigió usando un descriptor de escritura antes de repetir y aprobar la prueba.

**Límite:** es una prueba del controlador transaccional con tareas reales de Windows, pero **no ejecuta el motor DNS real, no mide conectividad externa real ni valida recuperación tras un corte eléctrico**. No está habilitado el reemplazo del DNS desde la aplicación instalada.

## Registro del motor realmente instalado (nuevo)

Se incorporó `motorupdate.InspectInstalledEngine` y `RecordVerifiedEngine`. El verificador **nunca identifica la versión por el nombre del archivo**: exige registro administrativo, manifiesto Ed25519 firmado, firma separada y SHA-256 del EXE instalado. Rechaza retrocesos, cambios de huella con versión repetida, inventarios alterados, archivos enlazados y ubicaciones ajenas.

El comprobador del botón `Actualizar VOLVÉ` consulta ese inventario para evitar descargar una versión anterior. Cuando el motor heredado 0.28.6 no tiene aún un registro verificable, **no inventa la versión** ni autoriza sustituir el servicio. La prueba de Windows con tarea SYSTEM desechable ya copia los tres archivos del paquete, confirma el inventario firmado cuando la transacción tiene éxito y comprueba que un rollback no registra la nueva versión.

**CI validado:** [GitHub Actions 40983028270](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40983028270), 3/3 jobs aprobados, pruebas Linux y Windows incluidas. Durante el desarrollo se corrigió un falso rechazo de rutas temporales de Windows que usaban nombres DOS 8.3 (`RUNNER~1`) sin ser enlaces: la comprobación de seguridad ahora examina los componentes reales mediante `Lstat`.

Este avance **no habilita la actualización del DNS real**; se debe conectar el inventario a un controlador administrativo real con respaldo, aislamiento de acceso y recuperación ante interrupción antes de publicar un release del motor.

## Cambio de tarea SYSTEM real y procedencia del motor anterior

Se comprobó en el código original que el servicio existente es la tarea `VOLVE-DNS-SERVER-0270`, con acción `VOLVE_DNS_Server_0270.exe --dns-service`, y que `VOLVE-DNS-RESCUE-0270` es un mecanismo de rescate separado. El motor heredado se instala como copia del ejecutable del Centro: **no se puede deducir su versión a partir del Centro actual**.

Se incorporó `motorupdate.VerifyLegacyMotorAttestation`: identifica un motor heredado solo si una declaración de procedencia firmada por el publicador (Ed25519) coincide exactamente con la tarea, nombre, argumentos, tamaño y SHA-256 del ejecutable real. Rechaza declaraciones manipuladas, binarios alterados, tareas suplantadas y JSON con datos extra. **Todavía no se ha publicado una declaración firmada para las instalaciones antiguas**.

Se incorporó `motorupdate.VerifyInternetTLS`, que usa el resolvedor de Windows para comprobar DNS + negociación TLS con certificados válidos en dos destinos externos, con tiempo límite. Incluye pruebas con servidores TLS locales confiables/no confiables, nombre incorrecto y cancelación.

Se extrajeron a `native_task_switch_windows.go` primitivas reales de Windows que verifican el paquete Ed25519 y la tarea SYSTEM original antes de cambiar su acción, y restauran únicamente un respaldo XML cuya huella SHA-256 y propiedad SYSTEM coinciden. Las pruebas de Windows ejercitan esas funciones **sobre tareas SYSTEM desechables**; no son simples simuladores. El cambio de la tarea **productiva** continúa bloqueado por código hasta que exista un watchdog independiente probado que recupere el motor anterior ante interrupciones.

## Recuperador independiente ejecutado por SYSTEM — piloto aprobado

Se añadió `cmd/volve-managed-watchdog`, un ejecutable Windows **separado** del Centro y del actualizador. Lee un journal de fases, comprueba que el respaldo XML sea un archivo regular íntegro mediante SHA-256, exige tarea SYSTEM y ejecutable original permitidos, restaura la tarea desde otro proceso y verifica el resultado. Si la fase es `committed` o `restored`, no vuelve a modificarla. Rechaza JSON adicional, caminos sospechosos, tareas ajenas al laboratorio y respaldos alterados.

La recuperación se ensayó con tareas temporales reales en Windows de dos maneras: como un proceso independiente del actualizador y **dentro de una tarea programada que se ejecuta bajo la cuenta SYSTEM**. El ensayo comprueba que el XML original se restauró y que el journal quedó en fase `restored`. Se corrigió una falsa alarma causada por la salida de progreso CLIXML de PowerShell en STDERR, que contaminaba la confirmación de recuperación. El watchdog ahora lee por separado STDOUT y STDERR.

**Resultado verificado:** [GitHub Actions 40986185615](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40986185615): 3 de 3 jobs aprobados, incluidos tests de rollback, controlador Windows y compilación del Centro de desarrollo.

**Límites importantes:** este recuperador tiene un filtro de seguridad estricto que **solo permite tareas de laboratorio `VOLVE-CI-ManagedMotor-*`** y no puede restaurar ni cambiar `VOLVE-DNS-SERVER-0270`. Todavía no se realizó una actualización real del motor DNS, ni se verificó la recuperación frente a un corte de energía de una VM real. Falta adaptar el mecanismo al servicio productivo con ACLs de SYSTEM, journal duradero independiente, verificación de inicio efectivo y una prueba real de reinicio durante actualización antes de permitir el despliegue.

## Watchdog preparado antes de la conmutación y arranque de Windows

- El laboratorio arma **primero** el respaldo XML duradero, el journal en fase `pending` y una tarea SYSTEM independiente con disparador `AtStartup`. Verifica identidad SYSTEM, ruta del recuperador y presencia de exactamente un disparador de arranque, **antes de conmutar** la tarea temporal del motor.
- Luego conmuta una tarea exclusivamente `VOLVE-CI-ManagedMotor-*` y activa el watchdog como proceso independiente bajo SYSTEM. Confirma que recupera la tarea original y que el journal pasa a `restored`.
- Una segunda prueba deja el journal en `committed` y comprueba que, aunque el watchdog SYSTEM se ejecute, **no restaura por error** la versión anterior.
- El recuperador rechaza XML fuera de la carpeta de la transacción, directorios enlazados y respaldos modificados. Verifica SHA-256 en Go y de nuevo **en PowerShell sobre los bytes usados para importar** el XML, evitando reemplazos entre comprobación e importación.
- **GitHub Actions aprobado:** [40987247654](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40987247654), 3/3 trabajos (Windows, Linux y ensayo de recuperación del Programador de tareas).

**Alcance real:** la tarea de laboratorio tiene disparador de arranque válido, pero **no se reinició físicamente ninguna máquina o VM durante esta batería**; el disparador se accionó manualmente en Windows para comprobar su funcionamiento. El watchdog sigue rechazando `VOLVE-DNS-SERVER-0270` y el botón de actualización **no puede reemplazar todavía el motor DNS de producción**. Antes de liberar la actualización falta probar la interrupción/reinicio real, controlar ACL de los respaldos persistentes, conservar y arrancar efectivamente el motor original y validar DNS/Internet después de la recuperación.

## Verificación de permisos de Windows sobre los respaldos (etapa actual)

Se añadió al recuperador independiente `verifyRecoveryACL`, una comprobación **de solo lectura** de las ACL efectivas de Windows, utilizando las API .NET de descriptores de seguridad y los SID (no los nombres localizados). Exige propietario SYSTEM (`S-1-5-18`) o Administradores (`S-1-5-32-544`), DACL protegida en la carpeta de transacción y ausencia de permisos de escritura, borrado o cambio de permisos otorgados a cuentas no autorizadas en el journal, respaldo y directorios intermedios.

En GitHub Actions se probó que una carpeta heredada/de propiedad del usuario fuera rechazada, que un respaldo protegido únicamente para SYSTEM/Administradores fuera aceptado, que añadir escritura para Everyone fuera rechazado y que una ruta fuera de la carpeta de la transacción no pudiera utilizarse. Las primeras ejecuciones descubrieron dos problemas del laboratorio: carga del módulo PowerShell Get-Acl y conservación de permisos explícitos de usuario al retirar herencia. Se corrigieron usando las API .NET de ACL y una DACL nueva, sin conservar las entradas anteriores.

**CI aprobado:** [ejecución 40988214483](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40988214483), **3/3 trabajos**, con pruebas Windows del recuperador y compatibilidad del Centro.

**Límite importante:** la comprobación de ACL está desarrollada y probada, pero **todavía no se exige en la ruta activa `run` del watchdog de laboratorio**. Falta conectar el control antes de cualquier cambio al servicio real, instalar un directorio persistente propio y asegurado bajo ProgramData, y comprobar que también sus directorios padres no puedan ser sustituidos por un usuario corriente. No equivale a un motor DNS actualizado ni a una prueba de un reinicio real de máquina.

## Verificación de ACL obligatoria al ejecutar el recuperador — piloto protegido

La protección por SID/DACL ya está **conectada al ejecutable de recuperación**: `run` rechaza un journal y su XML si el propietario, los permisos de escritura o los directorios intermedios no son seguros; esta comprobación se realiza **antes de actuar**, incluyendo si el registro dice `committed` o `restored`. Los permisos Unix `0600` no sustituyen los descriptores de seguridad de Windows.

Las pruebas de laboratorio recrean los respaldos y el journal con listas de acceso explícitas y protegidas para SYSTEM y Administradores. Se comprueba recuperación en un proceso aparte, recuperación desde una tarea real SYSTEM y rechazo de respaldo alterado. Una prueba adicional crea únicamente una carpeta desechable `%ProgramData%\\VOLVE-CI-MotorRecovery-*`, confirma que los permisos iniciales no son confiables, la asegura sin conservar entradas explícitas del usuario y verifica el rechazo cuando se concede escritura a Everyone; luego limpia esa carpeta. **No crea ni modifica el directorio de VOLVÉ productivo.**

El primer conjunto integrado superó [GitHub Actions 40990488696](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40990488696) con Windows, Linux y rollback (3/3).

**Límites pendientes:** el recuperador sigue restringido a tareas `VOLVE-CI-ManagedMotor-*`. Falta definir un árbol de instalación y journal productivo persistente con ACLs y propiedad confiables desde sus directorios padres, verificar el arranque y salud del servicio DNS anterior después de la restauración, y realizar un reinicio auténtico de máquina virtual durante la conmutación. Ninguno de estos pilotos autoriza publicar una actualización del motor DNS real.

## PASO 2 — Evidencia de identidad del motor DNS existente (solo lectura)

Se añadió `legacy_upgrade_readiness_windows.go` y el diagnóstico CLI `--motor-upgrade-evidence <ruta-absoluta-candidato>`. **No cambia tareas SYSTEM, adaptadores DNS, ejecutables, motor residente ni journal de rescate.** En la futura versión del Centro esta comprobación exige simultáneamente:

1. Ejecución como administrador y `preflightMotorUpgradeReadOnly` aprobado para el **motor real**: identidad exacta de la tarea `VOLVE-DNS-SERVER-0270`, scripts y tarea de rescate SYSTEM originales, registro DNS activo y pruebas locales IPv4/IPv6.
2. Atestación de procedencia de publicación `VOLVE_DNS_Legacy_Attestation.json` junto con `.sig`, firmada Ed25519 por la **misma clave de publicación fijada**. Comprueba que la declaración identifica la ruta/nombre/argumentos exactos del ejecutable heredado, y coincide con el tamaño y SHA-256 de los bytes realmente instalados. **La versión heredada jamás se infiere del nombre del EXE ni de la versión del Centro.**
3. Paquete candidato `VOLVE_DNS_Motor_<versión>.exe` con manifiesto/firma Ed25519, tamaño y huella exacta, versión superior a la heredada y compatibilidad con la versión del Centro.

Las pruebas Windows generan atestaciones y candidatos **de laboratorio** con una clave efímera común. Rechazan identidad o firma falsa, motor heredado alterado, candidato alterado, Centro demasiado antiguo, errores del preflight y cancelaciones. Ninguna prueba invoca la tarea DNS de producción.

**Limitación para avanzar al cambio real:** la atestación firmada para el motor heredado concreto de 0.28.6 **todavía no está publicada**. Por diseño este nuevo diagnóstico debe negarse a declarar elegible una instalación sin esa evidencia. También sigue activo el bloqueo expreso de `switchVerifiedMotorTaskAction` para `VOLVE-DNS-SERVER-0270`: no se ha habilitado el motor nuevo ni hay prueba de recuperación en un reinicio real de VM. El siguiente paso es generar/probar la atestación con el proceso legítimo del editor, enlazar el watchdog transaccional a una tarea productiva de prueba aislada y probar el arranque efectivo del motor.

## PASO 2 — Ensayo con el ejecutable completo de VOLVÉ, sin ejecutar DNS

Se agregó `complete_binary_action_recovery_windows_test.go` a las pruebas Windows. A diferencia del ensayo preliminar con Notepad, usa el **EXE completo del Centro VOLVÉ 0.28.7 compilado en CI** como paquete candidato, calcula su SHA-256, crea un manifiesto y firma **efímeros de laboratorio**, comprueba integridad Ed25519 y lo copia a una ubicación versionada. Esta firma **no es una firma de publicación**.

El ensayo arma primero un journal de recuperación protegido con ACL para SYSTEM/Administradores, su respaldo XML y una tarea SYSTEM con disparador de arranque. Luego cambia **solamente** la acción de una tarea desechable `VOLVE-CI-ManagedMotor-*` para apuntar al ejecutable real compilado, verifica su firma y acción, activa el recuperador independiente en una segunda tarea SYSTEM, y comprueba que restaura la acción original y el journal `restored`.

**Prueba real:** [GitHub Actions #41038998848](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41038998848), **3/3 jobs exitosos**. El ensayo `TestCompleteApplicationCandidateSystemTaskRecovery` pasó en Windows en 9,11 segundos.

**Límites:** el ejecutable compilado **NO se arrancó** en modo `--dns-service`, no se comprobó resolución real de DNS con él, no hubo cambio del adaptador ni reinicio de VM. El motor original del ensayo es `cmd.exe`, no el motor DNS real. El motor productivo `VOLVE-DNS-SERVER-0270` continúa mecánicamente bloqueado para el cambio. Aún falta la constancia firmada auténtica para el motor heredado instalado, un arranque real en VM aislada con recuperación del servicio DNS y pruebas de salud, antes de desplegar.

## PASO 2 — Motor DNS real en loopback temporal desde el ejecutable completo

Se añadió `motor_dns_isolated_probe_windows.go` y el comando de diagnóstico `--motor-dns-isolated-loopback` al Centro 0.28.7 de desarrollo. El comando invoca directamente **`dnsproxy.SelfTest()` del motor real**, que abre un servidor DNS UDP y un upstream ficticio sobre `127.0.0.1` en puertos asignados por Windows, envía cinco consultas reales, verifica **tres respuestas NXDOMAIN y dos permitidas**, detiene los sockets y devuelve un marcador de éxito estricto.

La CI de Windows **ejecuta el .exe completo compilado** con ese comando (no solamente pruebas de unidad), comprueba su código de salida y el marcador del resultado, y ensaya también los tests reales de sockets y failover del módulo `dnsproxy`. Antes y después toma una instantánea de los servidores DNS configurados en los adaptadores de Windows y verifica que **no cambiaron**; verifica además que no haya aparecido/modificado la tarea productiva `VOLVE-DNS-SERVER-0270`. Si las pruebas o la configuración no coinciden, CI falla.

**Aprobado:** [GitHub Actions #41042473099](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41042473099): **3/3 trabajos** (Windows, Linux, reversión). El proceso de prueba validó cinco consultas (3 bloqueadas, 2 permitidas).

**Límites decisivos:** este es el **código DNS real ejecutado desde la aplicación completa**, pero **NO** es la ejecución del servicio productivo `runDNSService()` en el puerto 53 ni una prueba del servicio con el adaptador del sistema apuntando al DNS propio. No se instalaron tareas ni se ensayó un reinicio real de Windows. El futuro reemplazo del motor residente permanece bloqueado. Para cerrar el paso 2 aún falta ejecutar y revertir el servicio real en una VM aislada con la atestación legítima del motor 0.28.6 y un watchdog de recuperación.

## PASO 2 — Catálogo Full real: 400.002 reglas y consultas DNS en Windows

Se separó el cargador `fullEngineAt(root)` del acceso a `installRoot()` **sin cambiar la carga de producción**: `fullEngine()` sigue resolviendo la ubicación de instalación y utiliza el mismo parser de Hagezi Full, con su mínimo de 400.000 entradas y listas complementarias opcionales. Esto permite probar el comportamiento real desde `t.TempDir()` en lugar de leer o alterar un catálogo instalado.

La prueba `real_catalog_motor_windows_test.go` construye un catálogo sintético **solo de prueba** con 400.002 dominios, verifica la carga con `fullEngineAt(root)`, inicia `dnsproxy.New(engine,...).Run()` sobre un puerto IPv4 UDP local temporal y comprueba tres respuestas NXDOMAIN por socket real. Además exige que se rechace tanto la ausencia del catálogo como un archivo con 300 registros. Nunca utiliza el puerto 53, modifica adaptadores, registra tareas ni cambia las reglas instaladas del usuario.

**CI confirmado:** [GitHub Actions #41044219957](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41044219957): **3 de 3 trabajos aprobados** (Linux, Windows y reversión). Pruebas de catálogo: `TestActualFullCatalogRejectsMissingFileAndShortCatalog` OK y `TestActualFullCatalogLoadsAndBlocksOnLiveWindowsUDP` OK (400.002 reglas, tres respuestas bloqueadas).

**Límite:** no se ha probado todavía `runDNSService()` completo escuchando IPv4/IPv6 en puerto 53, cargando un catálogo real de producción en una máquina virtual desechable ni sobreviviendo a un reinicio de Windows. El reemplazo de la tarea productiva sigue mecánicamente bloqueado. Siguiente objetivo: ensayo aislado del servicio residente con el catálogo real y reversión independiente del proceso.

## PASO 2 — Servidor residente real IPv4 + IPv6: código compartido y ensayos aislados

Se extrajo la rutina de inicio del servicio DNS residente a `runDNSServiceAt(ctx,root,port,upstreams,ready)` dentro de `production_dns_service_runner_windows.go`. El **comando productivo `--dns-service`** conserva la entrada `runDNSService()`, `installRoot()`, el puerto fijo **53**, los servidores upstream originales y la recarga de catálogos cada cinco minutos; ahora llama a la **misma rutina** que se usa en laboratorio. Si cambia inesperadamente el cuerpo original del servidor, `apply_overlay.go` rechaza el parche en lugar de modificar código desconocido.

Prueba `TestResidentDualStackDNSFullCatalogFromRealRunner`: desde una carpeta temporal construye 400.002 registros Full, levanta la rutina de servidor residente en **127.0.0.1 y ::1 simultáneamente** usando un puerto temporal distinto de 53 y un upstream local ficticio, procesa **cuatro bloqueos y dos respuestas permitidas** por UDP real, y comprueba el cierre al cancelar el contexto. También se probaron el rechazo de un catálogo Full ausente y la negativa a iniciar con el puerto IPv4 ocupado. El flujo de Windows CI toma una instantánea de los servidores DNS del sistema antes y después para confirmar que el ensayo no los cambió.

**Evidencia verificada:** [GitHub Actions #41046264454](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41046264454), **3/3 trabajos exitosos**. En el log Windows: `TestResidentDualStackDNSFullCatalogFromRealRunner` PASS, `TestResidentDNSRunnerFailClosedWithoutFullCatalog` PASS, `TestResidentDNSRunnerRejectsAlreadyBoundIPv4Port` PASS.

**NO equivale a una actualización productiva probada.** Este ensayo no abrió el puerto 53, no actualizó ni arrancó la tarea `VOLVE-DNS-SERVER-0270`, no utilizó el catálogo real del usuario, no configuró Windows para consumir el DNS propio, no reinició una VM y no probó que el motor instalado sobreviva a la actualización. El paso 2 sigue pendiente de un laboratorio VM desechable con el motor real, puente de versión firmado y recuperación independiente verificable tras reinicio, antes de desbloquear el actualizador productivo.

## PASO 2 — Primer ensayo en puerto DNS real 53, Windows VM alojada en GitHub

Se añadió `dns_port53_hosted_vm_windows_test.go`, que **solo permite** abrir `127.0.0.1:53` y `[::1]:53` en una **máquina virtual Windows efímera alojada por GitHub**. Se exige además una autorización de CI explícita, comprobación del entorno virtual, ausencia de las tareas productivas `VOLVE-DNS-SERVER-0270` y `VOLVE-DNS-RESCUE-0270` y disponibilidad de los cuatro listeners locales (UDP/TCP de ambas familias) ANTES de la prueba. Fuera de ese entorno, el ensayo se niega a ejecutarse.

El test comparte `runDNSServiceAt()` con la ruta productiva `--dns-service`. Construye 400.002 reglas de laboratorio en carpeta temporal, usa un upstream ficticio local y levanta el DNS residente en el **puerto 53 real**. Ejecuta por UDP consultas en IPv4 e IPv6: **cuatro NXDOMAIN y dos respuestas permitidas**. Al finalizar cancela el proceso y comprueba que el servidor deja de ejecutarse. GitHub Actions compara antes y después los servidores DNS configurados en los adaptadores de Windows y rechaza cualquier diferencia. No instala ni modifica tareas, ni configura Windows para usar ese DNS.

**Resultado comprobado:** [GitHub Actions #41049825576](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41049825576), **3/3 trabajos aprobados**. El log Windows incluye `TestResidentDNSPort53GitHubHostedVM PASS (0.48s)`: `real resident DNS loopback 53, IPv4 + IPv6, Full 400002, 4 NXDOMAIN, 2 forwarded`.

**Límite:** lo probado es la rutina real del servicio ejecutada dentro del proceso de pruebas en una VM Windows efímera, **no** la tarea SYSTEM productiva con su ejecutable instalado, el catálogo real del usuario ni una recuperación después de reiniciar. La instalación 0.28.6 del usuario no se ha modificado y el cambio de la tarea productiva sigue bloqueado. Siguiente objetivo: ensayo de instalación, conmutación de motor y watchdog tras un **reinicio real de VM**, con constancia firmada auténtica del motor heredado.

## Lo que falta para una actualización del motor sin reinstalar

- Registrar y verificar la versión/identidad real del motor que está instalado (no deducir de nombre de archivo).
- Implementar el controlador Windows `motorupdate.SwitchDriver` con respaldos inmutables, tareas SYSTEM verificadas, motor versionado, validación de DNS IPv4/IPv6 y conexión externa.
- Conectar journal + watchdog independiente a este controlador; validar reversión durante fallos y cortes, incluidos rechazos de respaldos alterados.
- Publicar un asset oficial del motor y su manifiesto Ed25519 **sin incluir la clave privada en GitHub**.
- Verificar el procedimiento en un Windows de prueba y generar el nuevo Centro apto para actualización desde 0.28.6; la firma Ed25519 del manifiesto actual es un requisito, no se debe falsificar.

**No publicar ni aplicar cambios sobre el motor de la PC real hasta pasar esas validaciones.**
