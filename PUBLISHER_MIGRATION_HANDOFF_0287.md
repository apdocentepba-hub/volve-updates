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

### Próximo avance de ingeniería independiente de la firma

Desarrollar el adaptador aislado que obtiene la identidad **real** de tarea SYSTEM y del ejecutable instalado, valida el recibo bajo ACL y pasa esos valores a la función de revisión. Primero ejecutarlo en VM y con guardas de no-mutación; no integrarlo al botón de actualización hasta tener permiso editorial y ensayo de reboot.

**Importante:** esta puerta sigue ABIERTA; el 50% se refiere al progreso de las tareas de laboratorio, no a la capacidad de actualizar automáticamente.
