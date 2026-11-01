# VOLVÉ 0.28.7 — Hito 6: autorización editorial de migración

**Fecha:** 31 de octubre de 2026 (Argentina). **Rama:** `feature/motor-updater-0287-pilot`.

## Estado auditable

- **Progreso global:** 50% (5 de 10 puertas ya acreditadas). No es confiabilidad ni disponibilidad para instalar.
- **Progreso de esta puerta 6:** 50% del trabajo subdividido en cuatro controles; **0% acreditado al global** hasta completar los cuatro.
- **CI Windows y Linux aprobada:** [#41258366599](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41258366599).
- **Entrega:** `development/0.28.7/inapp/legacy_publisher_review_packet.go` y pruebas. Se incluyen en `apply_overlay.go`; no se instaló ni publicó una actualización.

### Cuatro controles del hito 6

| Control | Criterio comprobable | Estado |
| --- | --- | --- |
| 6.1 | Identificar el motor anterior por bytes, SHA-256 y recibo original de rollback coherente, sin inferir versión | Código y pruebas de laboratorio aprobados |
| 6.2 | Verificar firma Ed25519, hash y compatibilidad del candidato; construir evidencia de revisión **sin firma privada** | Código y CI Windows/Linux aprobados |
| 6.3 | Obtener evidencia real del motor **instalado por el usuario** y cotejar la clave pública fijada del editor, sin usar huellas ficticias | Pendiente: no hay acceso al Windows instalado ni hay release nuevo firmado |
| 6.4 | Emitir/publicar permiso **real** de migración por el editor legítimo y validar la transición exacta; prohibir firma CI como sustituto | Pendiente: firma editorial auténtica no disponible |

### Contrato nuevo: revisión sin permiso

`BuildLegacyPublisherReviewPacketReadOnly` comprueba que el motor anterior instalado coincide **dos veces** con el respaldo local protegido; valida el XML SYSTEM respaldado, la firma del motor candidato, la versión mínima de Centro y el preflight de tarea/rescate/DNS. También vuelve a verificar la salud y los bytes antes de devolver el expediente. Los campos incluyen hashes y tamaños originales, hash del XML de tarea, versión/hash/tamaño del candidato, versión de Centro observada y huella SHA-256 **de la clave pública**.

El componente se marca exactamente `dns-engine-migration-review-only`, disposición `REVIEW_ONLY_UNSIGNED_NOT_A_PERMIT`. No contiene versión histórica supuesta, rutas personales ni clave privada; no altera motor, backup, DNS, tareas ni registro. **Este objeto no es un permiso de migración ni debe usarse como uno.**

Los tests cubren firmas ausentes, otros editores, bytes de motor alterados, respaldo corrupto, falta de respaldo, ACL padre/archivo insuficiente, preflight fallido en primera o segunda lectura, Centro incompatible, recibo de motor ya administrado, cancelación y rechazo de expediente sin firma como autorización.

### Bloqueos antes de actualizar un Windows real

1. El **editor legítimo**, con la clave privada guardada **fuera del repositorio y de CI**, debe cotejar el expediente de los bytes realmente instalados y firmar el JSON de permiso real `dns-engine-legacy-migration` correspondiente a esos hashes, la tarea `VOLVE-DNS-SERVER-0270`, el XML original y el candidato final.
2. Ese permiso debe pasar `VerifySignedUnversionedLegacyMigration` con la clave pública fijada del Centro. Un expediente sin firma o firmado con una clave temporal de pruebas jamás reemplaza esto.
3. Mantener la barrera productiva: faltan watchdog SYSTEM autónomo y seguro, controlador transaccional, reboot real en la **misma VM Windows persistente**, y pruebas de reversión adversas. **No cambiar ni detener el motor instalado** ni publicar stable.json/motor-stable.json.
4. Ningún CI GitHub-hosted equivale a un reboot persistente ni a pruebas del equipo del usuario. La verificación sobre el equipo real tiene que ser de solo lectura antes de autorizar una intervención.

### Avance de la conexión real con Windows (31/10/2026)

**Implementado en rama piloto:** `development/0.28.7/inapp/installed_publisher_review_windows.go` y sus pruebas. El ejecutable reconstruido incorpora una opción **explícita y de solo lectura** `--motor-publisher-review <ruta-al-candidato-firmado>`, ajena al botón corriente de actualización. No solicita UAC en la interfaz, no publica nada y no toca DNS, tareas, respaldos o ejecutables. Solo emite al administrador el expediente JSON de revisión sin firma después de verificar todas las condiciones.

**Conexión con fuentes OS reales:** `installRoot()`, `isAdmin()`, `taskQuery()`, `verifySystemTaskXML()`, `preflightMotorUpgradeReadOnly()`, `verifyResidentRunningMotorReadOnly()` y `checkSealedLegacyRecoveryACL()`. Antes de ofrecer el expediente, exige tarea SYSTEM y proceso activo, propiedad del DNS/53 IPv4+IPv6, XML actual idéntico al respaldado, SHA-256 del motor activo igual al respaldo, ACL protegidas y candidato auténtico con la **clave pública** embebida. Repite las consultas para detectar cambios concurrentes.

**Evidencia aprobada:** [CI Windows #41260532066](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41260532066). Se reconstruyó el proyecto real, compilaron todos los módulos y pasaron los casos de tarea ausente, XML distinto, PID distinto, permisos insuficientes, motor o candidato adulterado, clave de otro editor, preflight fallido y cancelación. La consulta nativa de Task Scheduler detectó que la VM de pruebas **no tenía** la tarea productiva y rechazó generar un expediente auténtico. Una regresión adicional modifica el XML en la segunda inspección y está sometida a [CI #41260636604](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41260636604).

**Fuentes de publicación:** al consultar GitHub, la única release registrada es `v0.28.6` (pre-release del Centro); **no aparece un motor 0.28.7 editorialmente publicado**. No se generó ni se puede atribuir una firma editorial legítima.

**Crédito:** el adaptador del control 6.3 está programado y probado en laboratorio, pero **el control no puede darse por aprobado hasta observar realmente la instalación del usuario**. Continúan acreditados **2/4 controles del hito 6** y **5/10 puertas (50%) del piloto**.

### Ruta real de instalación: catálogo ≠ motor DNS — 31/10/2026

**Implementado** (solo rama piloto, sin publicación):
- `motor_install_route.go` clasifica únicamente expedientes con seis inventarios completos y token Administrator: sin motor DNS, catálogo verificado solamente, motor heredado que necesita revisión firmada, motor administrado firmado o protección residual/contradictoria que exige auditoría. No declara protegida ni desprotegida la política de navegadores.
- `motor_install_route_windows.go` conecta exclusivamente las consultas nativas read-only: tareas, servicios, adaptadores DNS, archivos, propietarios TCP/UDP 53 y estado de recuperación. Ninguna ruta otorga permiso para instalar, limpiar, sustituir ni cambiar la red.
- `installed_motor_route_windows.go` agrega un comando diagnóstico **explícito** `--motor-route-readonly` en el ejecutable *piloto*, sin conectarlo al botón «Actualizar VOLVÉ». Emite JSON solo al administrador que lo ejecuta, sin subirlo a servidores ni escribirlo en disco.
- No se infieren los argumentos ni la ruta de la tarea de catálogo a partir del propio Scheduler. En ausencia de una definición editorial fijada y verificable, la tarea se reporta como no verificada y **no** habilita una instalación nueva.

**Evidencia:** GitHub Actions [#41261743766](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41261743766) aprobó clasificación y lecturas nativas Windows. [#41261901273](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41261901273) aprobó además los tests de la interfaz CLI incorporada al ejecutable reconstruido. Los casos negativos incluyen motor sin tarea, tarea sin motor, catálogo sin identidad fijada, `::1`, TCP/UDP 53 ocupados, servicio detenido, recibos huérfanos y archivos de recuperación. El runner no representa la PC del usuario.

**Diagnóstico del usuario todavía desconocido:** en la información local compartida previamente había una tarea `VOLVE-CATALOGO-0230`, ausencia de `VOLVE-DNS-SERVER-0270`, algún DNS de loopback IPv6 y bloqueos de apuestas observados. Ninguno de esos indicadores demuestra por sí solo un motor DNS administrado funcionando o la ausencia de protección de navegadores. No se ha ejecutado el nuevo diagnóstico sobre el equipo del usuario.

**Crédito:** progreso global **50% (5/10)**; puerta 6 permanece **2/4 controles aceptados** porque faltan la identidad concreta del motor instalado y el permiso auténtico firmado por el editor. Este diagnóstico no es un instalador, ni una publicación, ni una actualización productiva.

### Diagnóstico autónomo de Windows 0.28.6 — 31/10/2026 (sin reinstalación)

**Entrega real:** [GitHub Actions #41262649792](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41262649792), trabajo `standalone-readonly-audit` aprobado. Se generó el artefacto `VOLVE_0287_Diagnostico_Windows_SoloLectura_LAB` (ZIP de laboratorio, 4 archivos). **No es el Centro ni una publicación estable**.

- Binario de alcance reducido: `VOLVE_Diagnostico_0_28_7_Solo_Lectura.exe`, **5.514.752 bytes**. SHA-256: `5c2192c155dce26d11f665b254e53ca145f8fa0983cf3c077e8d5f9621c0dd10` (verificado por la CI y también después de descargar el ZIP).
- Lanzador optativo `VOLVE_Diagnostico_Solo_Lectura.cmd`: pide confirmación UAC para **inspeccionar** Task Scheduler, DNS y servicios; no instala ni arranca motores.
- Documentación `LEEME_DIAGNOSTICO.txt` y archivo `SHA256_EXE.txt` dentro del ZIP.
- El ejecutable solo enlaza `motorupdate` y un `main` separado, **sin** el Centro ni las rutas de conmutación, actualización, desinstalación y limpieza.
- Se revisó la fuente original real: `installRoot() -> filepath.Dir(statePath())`; `statePath() -> %ProgramData%/VOLVE-Browser-Filter/estado.json`. El workflow **verifica ese nombre directamente contra el Centro original** e inyecta la misma constante compilando el diagnóstico; si cambia, aborta. Si falta el marcador no produce una conclusión falsa.
- Un informe JSON acotado se crea en Descargas con nombre único, **nunca se sobrescribe uno existente**. No contiene credenciales ni los valores detallados de políticas de navegador; esos bloqueos **no se inspeccionan**. El informe solo declara ruta de revisión, no estado de seguridad absoluto.
- Los tests de Windows y los escenarios adversos de clasificación aprobaron. La CI se hizo en VM efímera, **no se ejecutó en la PC del usuario**.
- **Advertencia:** es un EXE de laboratorio **sin firma de editor para distribución**. No desactivar SmartScreen/Defender para instalarlo; usar solamente como prueba de diagnóstico con autorización consciente. La herramienta no actualiza el software.

**Progreso global sigue en 50%**. Este binario permite obtener la evidencia concreta que falta para decidir la ruta en la PC del usuario, pero no reemplaza la firma editorial auténtica ni la VM Windows persistente, watchdog o conmutación productiva. El paso 6 sigue abierto.

### Auditoría de navegador VS motor DNS del Centro 0.28.6 — 31/10/2026

**Hecho:** se añadió `browser_policy_inventory_windows.go`, que consulta exclusivamente tres rutas HKLM fijas de la 0.28.6: Chrome URLBlocklist, Edge URLBlocklist y Firefox WebsiteFilter/Block. Calcula contadores anónimos de valores numerados y datos inválidos, sin incorporar URLs ni historial al informe. Tener entradas en Registro **NO comprueba que los navegadores las apliquen**, y mucho menos que el motor DNS esté instalado.

**Integración:** el diagnóstico autónomo `auditcmd/main_windows.go` ahora devuelve `browser_policies` con los tres contadores, más `browser_policies_status`, **separados** de la ruta de motor DNS basada en seis observaciones. Si falla la lectura o no hay permisos, lo declara desconocido y no inventa protección efectiva.

**Pruebas Windows aprobadas:** [GitHub Actions #41263495317](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41263495317). Pruebas unitarias contra duplicados, omisiones, valores corruptos, inyecciones, cancelación y ejecución real read-only del Registro en VM. En la VM efímera se contaron Chrome=0, Edge=0, Firefox=0, lo que **no describe la PC del usuario**.

**Artefacto independiente:** `VOLVE_0287_Diagnostico_Windows_SoloLectura_LAB` #13066760394, cuatro archivos; EXE de 5.527.040 bytes, SHA-256 `dea0adac311321ce5ba8b2614ae9f936ce3cdf2e89bc427b20b728906ea86022`, comprobado tras descargar el ZIP además de GitHub CI. Diagnóstico **sin firma editorial de distribución**, no instalador ni release del Centro. No deshabilitar SmartScreen o Defender para ejecutarlo.

**Lo que realmente falta:** resultados de la máquina con Centro 0.28.6, firma auténtica del editor, controlador SYSTEM productivo con rollback, prueba de reinicio persistente y publicación compatible. **Progreso global 50% (5/10 hitos), puerta 6 abierta**; no se ha autorizado ni ejecutado una migración.

### Investigación de la tarea de catálogo y diagnóstico detallado de Windows 0.28.6 — 31/10/2026

**Evidencia del código original (sin usar evidencia no verificada de la tarea como fuente de identidad):** en el ZIP de código reconstruido y auditado por SHA-256, `catalog_windows.go` registra la tarea `VOLVE-CATALOGO-0230` bajo SYSTEM, ejecuta `%ProgramData%/VOLVE-Browser-Filter/VOLVE_Motor_0210.exe --refresh` y deja intactas tareas ajenas. El asset original `assets/VOLVE_Motor_0210.exe` tiene SHA-256 `e296f8402af8b6b5e5f533bd8013df89027ca73adc7bc72e55f0174c72125a69`. Son evidencias del **origen del código**, NO una firma digital editorial de publicación. Auditoría de código en [Actions #41264692180](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41264692180).

**Corrección del falso bloqueo diagnóstico:** el ejecutable autónomo anterior recibía `expectedCatalogExe=""`, por lo que una tarea de catálogo existente nunca podía superar la verificación de acción. Su respuesta `unverified-host-stop` no demostraba un fallo, ausencia de motor DNS ni vulneración de la tarea. Ahora el diagnóstico calcula el SHA-256 del motor de catálogo local, compara exclusivamente con el asset original registrado y verifica la tarea SYSTEM con ejecutable y argumentos fijados desde la fuente, no leídos del propio Scheduler. Si el motor cambia durante la consulta o difiere del original, invalida la conclusión de confianza y no permite una instalación.

**Informe ampliado:** `motor_install_evidence_summary_windows.go` conserva solo un resumen anónimo del mismo conjunto de seis inventarios: cantidad de tareas/servicios, existencia y correspondencia de motor de catálogo, presencia de ejecutables DNS heredados/administrados, DNS loopback IPv4/IPv6, ocupación UDP/TCP puerto 53, journals y respaldo. No exporta rutas ni argumentos de tareas, IP exactas, URLs, valores de Registro ni secretos. Los contadores de políticas de Chrome/Edge/Firefox continúan independientes de la prueba de DNS. Ningún indicador autoriza modificar una tarea, actualizar el motor o cambiar DNS.

**Prueba completa:** [GitHub Actions #41264972864](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41264972864) aprobada en Windows. Test con los bytes originales reales del asset del catálogo reconoció correctamente la tarea fuente, y al adulterar el archivo rechazó su identidad. Test de IPv6 loopback y port53 preservó los rastros aun con catálogo sin verificar. Archivo ZIP de laboratorio generado y descargado, inspección íntegra ZIP, 4 archivos. SHA-256 EXE `72cfcdb5324f216f4fb7fee1c4c18385976a5f20551b6b7c3bbe567acc2e3eb3` (5.538.304 bytes). **No se probó aún en la PC del usuario; sigue sin firma editorial de distribución.**

**Puertas:** se mantienen **5/10 = 50%** global. La puerta 6 sigue abierta hasta confirmar la identidad y estado de la instalación del usuario y contar con autorización editorial de migración auténtica; tampoco hay controlador SYSTEM productivo, ensayo de reinicio persistente, paquete firmado ni permiso de publicación. Nada fue instalado, desinstalado o cambiado en la PC del usuario.

### Próximo avance de ingeniería independiente de la firma

Desarrollar el adaptador aislado que obtiene la identidad **real** de tarea SYSTEM y del ejecutable instalado, valida el recibo bajo ACL y pasa esos valores a la función de revisión. Primero ejecutarlo en VM y con guardas de no-mutación; no integrarlo al botón de actualización hasta tener permiso editorial y ensayo de reboot.

**Importante:** esta puerta sigue ABIERTA; el 50% se refiere al progreso de las tareas de laboratorio, no a la capacidad de actualizar automáticamente.


### Evidencia de instalación heredada y expediente editorial sin firma — 31/10/2026

**Verificación privada en el equipo del usuario:** el diagnóstico 0.28.6 de solo lectura devolvió la presencia del motor DNS heredado y de su tarea SYSTEM; los dos sockets UDP/53 loopback IPv4/IPv6 tenían el mismo dueño y el proceso identificado correspondía a la ruta/argumentos heredados bajo SID SYSTEM. **Límite:** observación de identidad de proceso, no prueba positiva de consultas DNS bloqueadas, cadena de parentaje Scheduler, firma editorial, respaldo restaurable ni permiso para conmutar. No se incorpora al repositorio el JSON privado ni datos personales, rutas o PID.

**Avance en código (sin tocar Windows):** `auditcmd/legacy_publisher_baseline_windows.go` construye una **solicitud de identidad sin firma**, solo si la inspección existente demuestra el proceso SYSTEM exacto. Revisa por duplicado la tarea `VOLVE-DNS-SERVER-0270`, su ruta y argumentos, el ejecutable instalado, su SHA-256 y tamaño, y la huella SHA-256 del XML original leído mediante `schtasks /Query /XML`. La doble lectura detecta cambios entre instantáneas y devuelve `NOT_VERIFIED_NO_CHANGES` **sin hashes** si algo falla. No guarda XML, rutas completas, nombres de usuario, PID, URL, clave privada ni datos de navegación; no escribe DNS, Scheduler ni binarios.

**Condición de salida inalterada:** el campo `legacy_identity_for_publisher` con estado `UNSIGNED_LEGACY_IDENTITY_FOR_PUBLISHER_REVIEW_ONLY` es **solo una solicitud de revisión**, con `signature_verified=false`, `migration_authorized=false` y `ready_to_switch=false`; no es un recibo de recuperación ni una autorización. Solo un editor legítimo con la clave privada de producción, un candidato firmado compatible, backup seguro, driver con watchdog y VM Windows persistente puede habilitar una migración futura.

**Pruebas:** [Windows diagnóstico #41266391927](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41266391927) aprobó reconstrucción de la fuente original, compilación Windows y regresiones de tareas inválidas, procesos distintos, alteración de XML/EXE, cancelación y ausencia de una firma. El paquete final con LEEME actualizado corresponde a [CI #41266506300](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41266506300); consultar conclusión antes de distribuirlo.

**Estado:** 5/10 hitos (50%) global, hito 6 **abierto**. No se probó la nueva recolección de huellas en el Windows del usuario ni se publicó/instaló un motor nuevo. El Centro 0.28.6 continúa intacto.


### Identidad del motor 0.28.6 en la PC del usuario — diagnóstico de etapa 31/10/2026

El JSON compartido demuestra que el motor DNS heredado conserva ambos endpoints UDP/53 loopback IPv4 e IPv6 bajo el mismo proceso SYSTEM, pero la verificación adicional `legacy_identity_for_publisher` devolvió `NOT_VERIFIED_NO_CHANGES`, sin hashes ni autorización. Esto no refuta la existencia del proceso. El JSON privado del usuario NO se subió a GitHub.

**Corrección de código:** `development/0.28.7/auditcmd/legacy_publisher_baseline_windows.go` ahora informa un `failure_stage` seguro y acotado para distinguir fallos de propietario, ruta, argumentos, directorio de trabajo, ejecutable y XML de tarea, cambios entre observaciones y errores de lectura. Nunca incluye ruta local, PID, XML, contenido de tareas ni errores privados. Ante cualquier fallo omite hashes y no autoriza instalar, actualizar ni cambiar el DNS. La segunda observación de propietario ahora compara la evidencia booleana, no solo una cadena de estado.

**CI y paquete:** GitHub Actions https://github.com/apdocentepba-hub/volve-updates/actions/runs/41267081082, éxito en Windows. La primera prueba detectó que el fixture reutilizaba el puntero a evidencia; se corrigió con copia independiente y pasó la regresión de deriva de proceso. Artefacto #13068130647 descargado e inspeccionado: ZIP válido; SHA-256 EXE 72e5bf9e1ae93ea42ce32e9751980ee6b8868925d65753b69055938abf5fbca6. Diagnóstico experimental NO firmado para distribución, no un actualizador.

**Estado:** 50% global (5/10 hitos); hito 6 abierto. No existe permiso editorial productivo ni conmutación/recuperación validada sobre esta PC. Se requiere conocer `failure_stage` del equipo antes de revisar o suavizar cualquier verificación y antes de generar una autorización real de migración.


### Corrección del cotejo de ruta Scheduler 0.28.6 — 31/10/2026, 23:13 ART

El informe del Windows real confirmó que el análisis de identidad se interrumpía en `FIRST_TASK_ACTION_PATH_MISMATCH`. No se recibieron ni publicaron rutas de tareas privadas. Los datos independientes mostraban el proceso SYSTEM heredado dueño de los sockets UDP/53 locales IPv4/IPv6.

La auditoría del código original autenticado reconstruido de los diez segmentos fuente, en GitHub Actions #41267914339 y #41267978158, identificó que el propio Centro 0.28.6 crea su tarea con `quoteTaskScriptPath(exe) + " --dns-service"` y valida los comandos XML mediante `normalizedWinPath`. Esa rutina contempla comillas exteriores, separadores equivalentes, prefijo `\\?\` y segmentos `.`. El diagnóstico autónomo nuevo, en cambio, comparaba `Get-ScheduledTask.Actions[0].Execute` con `filepath.IsAbs` y `filepath.Clean` antes de quitar comillas, y podía rechazar una tarea legítima.

**Fix**: el comparador nuevo `compareLegacyTaskActionPath` acepta únicamente representaciones léxicamente equivalentes del MISMO ejecutable en la MISMA carpeta verificada, conservando todos los controles de propietario SYSTEM, exactamente una acción, argumento `--dns-service`, proceso DNS, doble lectura de la identidad y ausencia de permiso editorial. Rechaza carpeta distinta, nombre distinto, ruta relativa, comillas malformadas, expansiones de entorno, `..` y caracteres de comando. Expone solo `task_action_path_form`, una categoría sin rutas. No toca el Task Scheduler de la PC ni cambia el motor.

**Evidencia de CI**: GitHub Actions #41268238838 aprobó Windows nativo y las regresiones positivas/negativas, después de corregir un caso de test que requería tratar el prefijo DOS extendido antes del filtro de `?`. ZIP de laboratorio #13068113389 comprobado íntegramente en container (4 archivos, ningún miembro corrupto), tamaño 3.223.211 bytes, EXE 5.578.240 bytes, SHA-256 3d746c44038f32536c1d3d670ec655ce4853d643aa896ca6a99249a2ee692df7.

**Alcance y pendiente:** esta corrección no demuestra que el usuario tenga solo una diferencia de comillas: el diagnóstico nuevo debe observar el formato real. Si la ubicación difiere, se bloquea y registra la categoría, sin cambiar Windows. Faltan firma editorial, respaldo validado, controlador transaccional, reinicio persistente y revisión del usuario. Progreso global continúa **50% (5/10)**; no existe release o actualización productiva.

### 01/11/2026 — Identidad del motor instalado en PC real obtenida (no es permiso de migración)

En un informe local de solo lectura enviado voluntariamente por el usuario, `legacy_identity_for_publisher` alcanzó `UNSIGNED_LEGACY_IDENTITY_FOR_PUBLISHER_REVIEW_ONLY`. La acción de la tarea SYSTEM se reconoció como ruta equivalente del mismo ejecutable con comillas exteriores (`SOURCE_EQUIVALENT_OUTER_QUOTES`), confirmando que el `FIRST_TASK_ACTION_PATH_MISMATCH` anterior era un falso rechazo del diagnóstico. Se obtuvieron SHA-256 y tamaño del ejecutable heredado y SHA-256 del XML real de Scheduler, con proceso SYSTEM dueño de UDP/53 en loopback IPv4 e IPv6. **Los hashes reales no se publican en el repositorio**; deben manejarse como expediente de revisión, no como autorización.

**Sin nuevas credenciales ni autorización:** `signature_verified=false`, `migration_authorized=false`, `ready_to_switch=false`. El informe no identifica ni verifica aún un motor destino firmado, la clave editorial fijada del candidato, un respaldo NTFS protegido y recuperable, un journal ni pruebas de conmutación/reinicio. Por tanto la puerta 6.3 continúa incompleta en su contrato íntegro (identidad real obtenida, vinculación a editor/candidato pendiente) y la puerta 6.4 no está acreditada. La presencia de una escucha TCP/53 IPv6 adicional en esta observación merece una comprobación separada de propietario antes de conmutar o afirmar disponibilidad de DNS; no se interpreta como falla de protección sin más evidencia.

**Marcador de aceptación:** se mantienen 5/10 hitos globales (50%) y el hito 6 NO se acredita. El próximo avance útil es preparar candidato editorial compatible, evidencia verificable de firma y backup/restore, no repetir diagnósticos de identidad ya superados. No modificar tareas, DNS ni componentes del Windows del usuario.


### 01/11/2026 — Vinculación previa de informe real con candidato editorial firmado (solo laboratorio)

**Implementado:** `development/0.28.7/inapp/legacy_observed_candidate_review.go` + tests, integrados al proyecto reconstruido mediante `apply_overlay.go`. `BindUnsignedHostReportToSignedCandidateReadOnly` analiza un diagnóstico local de solo lectura para construir una solicitud de revisión de un motor heredado y lo relaciona con un candidato nuevo cuya firma Ed25519, huella, tamaño y versión se verifican con `VerifyStaged` y la clave pública editorial suministrada. Rechaza versiones inferiores a 0.28.7 y paneles incompatibles, repite la verificación del candidato, rechaza JSON con propiedades duplicadas y omite rutas, PID y datos de navegador.

**Barrera obligatoria:** el informe de usuario se considera **no confiable por sí solo**. El objeto resultante es `UNTRUSTED_HOST_REPORT_PLUS_SIGNED_CANDIDATE_NOT_A_PERMIT`; declara `requires_protected_rollback=true`, `legacy_identity_independently_verified=false`, `migration_authorized=false` y `ready_to_switch=false`. No valida ni crea backup/ACL, no inspecciona de nuevo el proceso real, no firma el expediente ni conmuta DNS. El `LegacyPublisherReviewPacket` de mayor exigencia sigue requiriendo rescate protegido y preflight Windows independiente, y `VerifySignedUnversionedLegacyMigration` sigue exigiendo permiso editorial verdaderamente firmado.

**Evidencia:** [Windows y Linux CI #41269240819](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41269240819) COMPLETADA CON ÉXITO. En ambas plataformas se probaron casos de emparejamiento sintético, candidato de otro editor, bytes alterados, versión de panel incompatible, información de proceso/tarea suplantada, JSON duplicado y rechazo del expediente por el verificador de permisos. Se utilizaron claves efímeras de prueba y huellas sintéticas, **nunca las claves privadas editoriales ni los hashes reales del usuario en GitHub**.

**Bloqueo remanente:** no se dispone de candidato de producción 0.28.7 firmado por la clave editorial fijada en Centro; tampoco existe autorización firmada, backup de la instalación protegida/confirmada, watchdog productivo ni validación de conmutación tras reinicio real. Por tanto el hito 6 sigue **ABIERTO** y el avance global permanece **50% (5 de 10 puertas)**. No solicitar nuevos diagnósticos de identidad ya aprobados salvo que cambie la instalación.


### 01/11/2026 — Control transaccional: respaldo íntegro después de Snapshot (hito 7 parcial)

Se reforzó `development/0.28.7/inapp/legacy_managed_transaction.go`. El contrato firmado 0.28.6 → 0.28.7 ya exigía un respaldo original protegido para evaluar el permiso; ahora **vuelve a verificar los bytes y el XML del respaldo inmediatamente después del callback `Snapshot`, antes de preparar siquiera un candidato versionado**. También verifica el respaldo antes y después de cualquier intento de recuperación iniciado por un fallo posterior al respaldo.

**Riesgo mitigado:** un cambio de permisos, un archivo XML eliminado, un ejecutable de recuperación adulterado o un recibo corrupto no pueden pasar a `InstallVersionedCandidate`, `Switch` o `Commit`. En caso de respaldo inválido, el controlador devuelve **CRÍTICO** y **no llama a `Restore`** para no ejecutar un respaldo no confiable. Es una condición que requiere recuperación externa/diagnóstico; jamás se declara recuperación exitosa automáticamente. Con respaldo íntegro, se conserva el flujo existente de recuperación con contexto independiente, consulta DNS local e Internet. Cualquier implementación productiva del driver debe cumplir esa precondición y conservar un journal pendiente hasta verificación independiente.

**Pruebas de regresión (sintéticas, NO producción):** `TestSignedLegacyTransactionRejectsBackupModifiedImmediatelyAfterSnapshot` inyecta binario corrupto, XML ausente, recibo inválido y ACL revocada, y exige cancelación sin preparar un motor ni restaurar desde datos adulterados. `TestSignedLegacyTransactionRejectsSealedBackupTamperedAfterTargetPreparation` altera el XML protegido luego de preparar un candidato de laboratorio y comprueba que no se llega a `Switch` ni a `Commit`. [CI Windows/Linux #41269987143](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41269987143): **SUCCESS** en ambos sistemas. Workflows sin cambios de DNS productivo ni de tareas reales. La ejecución general #41269822446 estaba en curso durante esta anotación.

**Estado de aceptación:** el hito 7 sigue **abierto**, pues todavía falta un driver productivo que garantice inmutabilidad, exclusión mutua y watchdog independiente bajo SYSTEM, además de ensayos de recuperación con reinicio persistente. El hito 6 sigue abierto por falta de editor y candidato firmados. **Progreso global 50% (5/10 hitos), sin despliegue ni claves privadas de producción.**


### 01/11/2026 — Hito 7: evitar falso «restaurado» tras cambio del respaldo durante el arranque

**Cambio real en `motorupdate`**: `RecoverPendingResidentAfterBoot` ahora separa explícitamente la auditoría de salud (`AuditResidentRecoveryOutcome`) de la escritura del recibo, vuelve a llamar a `driver.VerifySealedOriginal` **después** de comprobar identidad SYSTEM, DNS local e Internet, y reabre el journal verificando que siga pendiente y corresponda al mismo `ResidentRecoveryIntent` antes de `FinishResidentRecoveryIntent`. Si el respaldo cambió durante las sondas no escribe `resident-result.json`: deja la operación pendiente y devuelve error. El controlador solo actúa con el mutex exclusivo del driver; no cambia la tarea instalada del usuario.

**Pruebas agregadas:** `TestBootRecoveryRechecksSealedOriginalAfterHealthyDNSBeforeTerminal` y `TestBootRecoveryNeverWritesRestoredReceiptWhenOriginalChangesAfterRestore`, en laboratorio. En Windows se añadió `TestResidentCIBootDriverRejectsBackupDriftDuringDNSProbe` que altera realmente el ejecutable del respaldo del fixture protegido durante la prueba DNS y exige que la segunda comprobación rechace la instantánea, sin escribir recibo ni invocar un restorer. El primer CI enfocado [#41270466047](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41270466047) aprobó Windows y Linux. El fixture reforzado que exige modificación real y error específico **APROBÓ en Windows y Linux**: [CI #41270590189](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41270590189). En Windows se ejecutó `TestResidentCIBootDriverRejectsBackupDriftDuringDNSProbe` y devolvió PASS tras alterar la copia original y comprobar el rechazo por la verificación posterior a DNS. Este ensayo no equivale a un reinicio real de Windows.

**Distinción crítica para el controlador futuro**: el adaptador `residentCIBootDriver` es exclusivamente de VM de laboratorio. Su `auditPendingResidentChain` exige que el ejecutable original todavía esté instalado (apropiado para el fixture CI previo al cambio); el watchdog **productivo** que detecte un cambio ya efectuado debe verificar la copia original protegida de forma independiente al ejecutable activo, y **no** usar sin cambios ese adaptador de laboratorio. También deberá validar identidad SYSTEM, mutex global compartido, journal persistente, exactitud del permiso firmado y pruebas tras reinicio real de Windows. No confundir pruebas de reinvocación simulada con reinicio físico de la misma VM.

**Aceptación**: hito 7 parcial; **50% global / 5 de 10 hitos** inalterados. Hitos 6, 7, 8, 9, 10 abiertos. No hubo modificación de DNS, tareas o ejecutables en la PC del usuario, ni publicación firmada.


### 01/11/2026 — Recuperación post-switch: motor instalado distinto/ausente, sin relajar la prevalidación

**Bloqueo técnico detectado:** `watchdogcmd/resident_recovery_chain_windows.go` comprueba `auditPendingResidentChain`, que exige que el ejecutable activo `VOLVE_DNS_Server_0270.exe` tenga exactamente el SHA-256 del respaldo. Eso es correcto como prueba **previa** al cambio, pero hace imposible iniciar la recuperación si el ejecutable original ya fue reemplazado o desapareció. El `residentCIBootDriver` y `restoreResidentPilotSYSTEMTaskWithRunner` aún utilizan esta comprobación previa. **No declarar restauración post-switch implementada.**

**Corrección incorporada:** nuevo verificador no destructivo `watchdogcmd/resident_post_switch_recovery_audit_windows.go` con `auditPostSwitchResidentRecovery`. Correlaciona la copia original del ejecutable + XML SYSTEM protegidos por NTFS y SHA-256 con el journal `recovery-required` y la identidad objetivo, repite la comprobación del respaldo y journal para detectar cambios, y **no exige que el ejecutable original esté todavía instalado**. Devuelve evidencia exclusivamente de recuperación, no permiso editorial para conmutar tareas ni ejecución del archivo. No altera DNS, tareas ni archivos. El verificador previo `auditPendingResidentChain` queda intacto y sigue rechazando ejecutables reemplazados.

**Pruebas reales Windows en VM efímera:** [GitHub Actions #41271454079](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41271454079) COMPLETADA SUCCESS. Incluyó casos de exe original ausente, reemplazado o intacto; respaldo EXE/XML adulterado, recibo ausente, journal incoherente/terminal, archivos extra, raíz insegura y cancelación. Los tres casos válidos devolvieron evidencia; los inválidos fueron rechazados. El journal no se consumió ni se creó recibo de éxito. Estos son fixtures locales: no se hizo un reboot real ni se modificó la PC del usuario.

**Siguiente cierre material pendiente:** implementar un adaptador SYSTEM de producción separado del CI, vinculado al permiso **realmente firmado** de migración, capaz de restaurar los bytes de origen desde el respaldo sellado si el original falta/está reemplazado, después reponer exactamente la acción de tarea programada, usar el mismo mutex global, confirmar DNS IPv4/IPv6 + red, y escribir recibo solo tras probar salud. Ensayar esos pasos con una VM Windows persistente que reinicie de verdad. El adaptador de laboratorio actual no sirve para post-switch porque todavía exige el ejecutable antiguo presente; no reutilizarlo como si el cambio ya estuviera resuelto.

**Estado:** 50% (5/10 hitos); puertas 6, 7, 8, 9 y 10 abiertas. No hay release editorial, firma auténtica ni despliegue autorizado. Priorizar una prueba de **restauración real en VM** sobre más diagnósticos de la misma instalación.


### 01/11/2026 — Archivo original efectivamente reconstruido desde respaldo sellado en Windows CI

**Nuevo avance funcional de laboratorio:** se incorporó `watchdogcmd/resident_post_switch_file_restore_ci_windows.go` y sus regresiones. `restoreMissingLegacyExecutableCILab` usa la auditoría del respaldo **posterior al cambio**, valida la correlación con el journal pendiente, limita la ejecución a `GITHUB_ACTIONS=true`, a un nombre de tarea descartable `VOLVE-CI-ManagedMotor-*` y a una raíz canónica bajo el árbol temporal de CI. Recupera los bytes exactos del ejecutable original protegido, los escribe con `fsync` en un archivo de staging y los publica mediante un enlace NTFS exclusivo sin sobrescritura. Verifica SHA-256 e identidad del respaldo de nuevo antes y después de reconstruir el archivo. Si la ruta de origen ya está ocupada por un ejecutable distinto, **no la sobrescribe**: esa sustitución requiere un control de proceso, mutex, permisos y tarea programada todavía no implementado. No modifica DNS ni Task Scheduler, ni escribe recibo de éxito.

**Evidencia verificable:** [CI #41271800893](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41271800893) **SUCCESS** en Windows. Aprobaron `TestPostSwitchCILabActuallyRecreatesMissingLegacyExecutableFromSealedBackup` (reposición real en disco), `TestPostSwitchCILabRefusesToOverwriteDifferentInstalledMotor`, `TestPostSwitchCILabNeverPublishesCorruptedFallback`, `TestPostSwitchCILabOnlyAcceptsDisposableTaskAndTempRoot`, además de la regresión previa de identidad cuando el motor falta o fue reemplazado. El journal siguió pendiente; ninguna prueba pudo declararse restauración completa sin verificar tarea SYSTEM y DNS.

**Límite deliberado:** la función solo existe como capacidad de laboratorio; la migración de producción sigue bloqueada. No existe aún un executor privilegiado que haga sustitución coordinada cuando hay un archivo distinto, restaure y verifique la tarea programada, confirme DNS IPv4/IPv6 y red, se recupere tras un reinicio real persistente, y verifique un permiso de editor verdaderamente firmado antes de realizar mutaciones. Para terminar VOLVÉ, el próximo paso de desarrollo debe probar en una máquina Windows descartable una **restauración completa de archivos + tarea SYSTEM**, no generar más informes de solo lectura.

**Estado general:** 50% (5/10 hitos) sin nuevos créditos de puertas 6–10. Este avance reduce un bloqueo específico del hito 7, pero no es apto para la PC del usuario, ni un release 0.28.7 firmado.


### 01/11/2026 — Primera restauración real conjunta: archivo + tarea SYSTEM descartable en Windows

**Código añadido:** `watchdogcmd/resident_post_switch_file_task_ci_windows.go` y `resident_post_switch_file_task_ci_windows_test.go`. `restoreMissingOriginalAndDisposableTaskCILab` utiliza el mismo mutex global CI que el watchdog de laboratorio, reconstruye primero el ejecutable ausente desde la copia NTFS/sha256 protegida y luego ejecuta `restoreResidentPilotSYSTEMTaskWithRunner`, que verifica de nuevo la cadena completa y restaura **una tarea real** de Task Scheduler bajo `SYSTEM` con una única acción `--dns-service`. El ámbito está limitado a `GITHUB_ACTIONS=true`, `RUNNER_ENVIRONMENT=github-hosted`, tareas `VOLVE-CI-ManagedMotor-*` y carpetas de prueba temporales. El ejecutable del ensayo es inerte; nunca se arranca DNS ni se modifican adaptadores. La tarea temporal se retira al finalizar.

**Defecto real encontrado y reparado:** la primera prueba integrada [CI #41272316133](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41272316133) falló con `Register-ScheduledTask : The task XML is malformed (1,40): ERROR unable to switch the encoding` (`0x8004131a`). El motor de recuperación validaba correctamente el SHA-256 de los bytes XML originales, pero le pasaba a Task Scheduler una cadena COM UTF-16 con una declaración `encoding=UTF-8`. Corregido en `resident_pilot_restore_windows.go`: tras verificar el original, se quita **solo la declaración XML en la cadena en memoria** antes de importar; el backup queda byte por byte idéntico. Regresión de script incorporada en `resident_pilot_restore_windows_test.go`.

**CI verificable:** [ejecución dedicada Windows #41272656067](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41272656067) **SUCCESS**, incluye `TestPostSwitchSystemTaskCILabRestoresRealDisposableSystemTaskAndMissingExe` con `PASS: real disposable SYSTEM task and original EXE recovered in Windows VM; journal still pending; DNS untouched`. También aprobaron los rechazos de motor instalado diferente, tareas productivas, ejecutores no autorizados y la regresión de codificación.

**Qué se comprobó:** en una VM Windows alojada por GitHub se registró una tarea SYSTEM de nombre único y acción hacia un motor nuevo inerte, se borró el ejecutable original de la carpeta descartable, se recuperó ese archivo desde el respaldo sellado y se reimportó la tarea original. Windows confirmó la acción SYSTEM restaurada. El journal quedó **`recovery-required`**, sin escribir falsos recibos `restored`. Ni red ni tareas VOLVÉ reales fueron modificadas.

**Siguientes bloqueos de aceptación, en orden:** (1) repetir archivo+tarea con un motor DNS de laboratorio funcional y verificar DNS local en 127.0.0.1 y ::1, catálogo y conexión de red; (2) interrupción antes/después de la escritura con watchdog SYSTEM independiente, registro durable y mutex; (3) repetir en una VM Windows persistente con **reinicio real**; (4) permiso editorial y candidato 0.28.7 auténticamente firmados, controlador productivo restringido a identidad exacta, integración con botón del Centro e instalación 0.28.6; (5) prueba integral sobre Windows real bajo autorización específica. Una recuperación en VM efímera no cubre puntos 2–5.

**Crédito global se mantiene 50%=5/10.** Hito 7 mejoró sustancialmente en integración de laboratorio, pero sigue **abierto**, como los hitos 6, 8, 9 y 10. No existe release ni migración desplegable en la PC del usuario.


### 01/11/2026 — Primer DNS/53 REAL después de restauración conjunta EXE + tarea SYSTEM (VM CI)

**Implementado:** `development/0.28.7/inapp/watchdogcmd/resident_post_switch_real_dns_ci_windows_test.go`, integrado a `apply_overlay.go`, y workflow dedicado `.github/workflows/volve-0287-post-switch-dns53-windows.yml`. El ensayo usa un **ejecutable DNS mínimo de prueba escrito para CI**, NO el motor de producción ni el motor 0.28.6 del usuario. Compila el ejecutable en Windows, recrea el respaldo protegido NTFS y su recibo SHA-256 y el journal sintético pendiente, sustituye temporalmente la acción de una tarea única `VOLVE-CI-ManagedMotor-*` por un candidato inerte, borra el ejecutable original y ejecuta `restoreMissingOriginalAndDisposableTaskCILab` para reconstruir archivo + tarea SYSTEM. Luego arranca efectivamente la tarea recuperada y consulta UDP/53 desde el proceso de prueba externo en IPv4 `127.0.0.1` e IPv6 `::1`.

**Resultado positivo con evidencia:** [Windows CI #41304036745](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41304036745) `SUCCESS`: `TestPostSwitchRestoredSystemTaskActuallyServesDualStackDNS53CILab` pasó. Para ambas familias DNS, consultas `stake.com` y `betwarrior.bet.ar` devolvieron NXDOMAIN (rcode 3) y `example.org` NOERROR (rcode 0), según reglas simples del fixture. El test validó que UDP/53 en ambas familias pertenecía al **mismo proceso SYSTEM** ejecutando el archivo recuperado y no escribió resultado final; el journal siguió `recovery-required`. Solo se registró una tarea disposable en VM GitHub alojada, con limpieza explícita; no hubo DNS real ni cambios de red en la PC del usuario.

**Regresiones/correcciones concretas:** la ejecución general previa [#41272847247](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41272847247) detectó `Get-FileHash` no disponible en Windows PowerShell durante `restoreResidentPilotSYSTEMTaskWithRunner`, reemplazado por lectura SHA-256 de un stream .NET. La prueba dedicada [#41303405918](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41303405918) volvió a pasar. La nueva prueba DNS necesitó eliminar un import sin uso (fallo #41303817486) y compilar el ejecutable en un archivo de staging separado para no sobrescribir un EXE preexistente (fallo #41303907508), y solo se declara aprobada tras el `SUCCESS` #41304036745.

**Limitación esencial:** probar un fixture DNS con UDP/53 NO demuestra que el motor VOLVÉ restaurado cargue su catálogo real ni que proteja navegadores. Este ensayo no instala ni valida el watchdog persistente productivo, no ejecuta un REINICIO REAL de la misma VM, no recibe permiso firmado auténtico, no repara el caso de un ejecutable destino diferente que ya ocupa la ruta, y NO autoriza una migración en la PC del usuario. La etapa siguiente debe usar el motor VOLVÉ CI de 400k+ entradas bajo SYSTEM en el circuito de restauración o una VM persistente para reinicio completo; luego la firma del editor y el controlador final.

**Estado 50% (5/10 puertas):** hitos 6–10 abiertos. El hito 7 tiene ahora evidencia real de archivo + Scheduler + DNS básico en el mismo ensayo; su contrato productivo exige controles adicionales.
