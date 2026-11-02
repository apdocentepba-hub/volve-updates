# VOLVÉ 0.28.7 — Estado verificable, 01/11/2026

**Objetivo:** actualizar el motor DNS desde el Centro 0.28.7 sin reinstalar y con reversión automática segura. Rama de trabajo: `feature/motor-updater-0287-pilot`.

## REALIZADO
- Centro v0.28.7 instalado en Windows real mediante el lanzador v0.28.6 (capturas del usuario), sin sustitución de motor.
- Paquete candidato 0.28.7 con firma editorial Ed25519 verificado en [Windows CI #41361613951](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41361613951); aún NO publicado como motor y NO instalado.
- [Windows CI #41360915352](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41360915352): ejecutable oficial probó DNS real bajo SYSTEM en tarea descartable y watchdog independiente restauró esa tarea.
- Auditoría de arranque protegida extendida: commit [c987e46](https://github.com/apdocentepba-hub/volve-updates/commit/c987e46eedbcadc08bc56cf48c7e7a7f71fde84f) exige evidencia editorial firmada para considerar admisible una recuperación PENDIENTE, además de coherencia del registro y respaldo. Solo lectura, NO activa cambios productivos.
- Recuperados diagnósticos anteriores del propio usuario:
  - `VOLVE_Diagnostico_Solo_Lectura_20261101_032106.075642600.json` (observación 03:20:58 UTC) incluye la identidad heredada para revisión: task `VOLVE-DNS-SERVER-0270`, argumento `--dns-service`, EXE `VOLVE_DNS_Server_0270.exe`, SHA-256 `8659d948427e515e3471508487c81afadb6c9cecfd3633aedc6ea67459f1d72a`, tamaño `14858240`, tarea XML SHA-256 `8ef1b3e43ce4c8fbbf71253dea913fab5ca182d3dd1218eb653a1d0035c3fafd`. **Diagnóstico histórico sin firma; no es autorización actual de migración.**
  - `VOLVE_DNS53_LEGIBLE_20261101_173700.json` muestra tarea/ejecutable SYSTEM y consultas A/AAAA bloqueadas/permitidas en 127.0.0.1 y ::1.
- Preparado **offline y fuera del repositorio** un permiso editorial Ed25519 para ese origen concreto y destino firmado v0.28.7 (nuevo motor SHA `e451b6289116636986ddd67b39dc15f02e471ebde7be9508b38d7bcb0155b414`, 18.168.832 bytes). Validado independientemente con Python cryptography y Go crypto/ed25519 + campos estrictos y vigencia. Vigencia `2026-11-01T23:43:23Z` a `2026-11-08T23:43:23Z`. Archivo generado de conversación `VOLVE_0287_Permiso_Editorial_Firmado_NO_INSTALAR.zip` (SHA256 del ZIP `8b9f9ec7bc14cc32f35e1d6df96b95b6cc0bbd07a194f23455bbb85e98f36c67`). **No está en Git, ni en el canal de actualización ni en la PC.** La clave privada original permanece en biblioteca; la copia temporal fue eliminada del entorno de trabajo.

## COMPROBADO
- Windows CI de firma de paquete y tareas descartables: exitosos (enlaces arriba).
- Nuevas pruebas de admisión firmada: Linux y reversión de Scheduler `success` en [CI #41362314542](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41362314542), Windows watchdog aún `in_progress` en la última consulta, no afirmar aprobación.
- La versión del Centro instalada en PC no demuestra por sí sola la versión del motor; documentos de identidad históricos no sustituyen nueva evaluación bajo el mutex de producción.

## PENDIENTE / CRITERIOS PARA LIBERAR EL MOTOR
1. CI Windows completo del nuevo filtro de admisión editorial y una restauración posterior a **reinicio real de VM persistente** (el ensayo alojado por GitHub fue sin reinicio real).
2. Controlador productivo SYSTEM que restaure el EXE original, tarea XML y DNS ante fallo, con mutex global compartido, ACL NTFS seguras, verificación doble de identidad, respaldo protegido y watchdog registrado.
3. Comprobar de nuevo en PC, justo antes de actuar, que SHA-256 del motor en uso, task XML, proceso SYSTEM y DNS v4/v6 coinciden con los hashes autorizados. El diagnóstico de 03:20 no es suficientemente reciente por sí solo.
4. Verificar que existe y está protegido el respaldo del motor anterior. El diagnóstico histórico indicaba `recovery_artifacts_seen=false`; no suponer su existencia.
5. Publicar motor en canal `releases/motor-stable.json` **solo después** de pruebas de recuperación, firma, interrupciones, compatibilidad y controles de salud. El canal sigue ausente.

## SIGUIENTE PASO
Esperar el resultado del ensayo Windows ya iniciado, corregir posibles regresiones del watchdog y desarrollar/ensayar driver real de restauración en entorno aislado. **No pedir reinstalación del Centro**; no ejecutar el permiso firmado ni cambiar DNS en la PC.

Este documento registra un avance verificable, no declara listo el actualizador productivo.

## Continuación — decisión de archivo original bajo permiso firmado

- Commit [e97328c](https://github.com/apdocentepba-hub/volve-updates/commit/e97328c1912cf2dd2b1bd0a879bfe7a022fa73e6) incorpora la clasificación READ-ONLY del archivo del motor original **DESPUÉS de autenticar el permiso editorial** y bajo el mutex de transición: `original-intact`, `missing-original`, `exact-pinned-target-still-present`. Cualquier archivo desconocido, de enlace o fuera de límites rechaza la admisión; se vuelve a comprobar el hash antes de cerrar el informe.
- No se ejecutan tareas, se detienen procesos ni se modifica DNS. La clasificación de archivos NO puede autorizar la sustitución por sí sola.
- Workflow específico [#41364443978](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41364443978), casos de firma auténtica, falsificación, inexistente, original intacto, ausente, destino exacto, alteración y symlink. **No declarar aprobado mientras esté in_progress**.
- El control completo de [CI #41364244698](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41364244698) aprobó Linux y rollback de Scheduler; la parte Windows requiere resultado final.
- Queda pendiente lo esencial: un driver real SYSTEM que valide tarea y proceso, cierre de forma segura el motor candidato si corresponde, restaure respaldo protegido, recupere DNS local, compruebe Internet, revalide el permiso y finalice sin falsos éxitos. Además, reinicio real en Windows persistente antes de liberar el canal del motor.


## Actualización técnica 02/11/2026 UTC — Task Scheduler y quiescencia DNS53

**REALIZADO:** agregado control de solo lectura de tarea `VOLVE-DNS-SERVER-0270` bajo SYSTEM, acción y argumentos exactos, inventario de procesos y puertos UDP/TCP 53. Rechaza datos incompletos, permisos insuficientes, otro ejecutable o puerto ocupado. Commit `fec7d0c` (código), `321472b` (ensayo real).

**REALIZADO:** integración del control anterior con firma Ed25519, hashes del journal/respaldo y doble comprobación del ejecutable **dentro del mismo mutex Windows**. Commit `b4e1618`. No habilita ninguna escritura productiva.

**COMPROBADO:** [Windows #41365598655](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41365598655) SUCCESS, tarea SYSTEM descartable, rechazo de tarea modificada, borrado de fixture. [Windows #41366011213](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41366011213) SUCCESS: bloqueo compartido, autorización firmada y rechazo si DNS53 sigue ocupado. Corrigió el import faltante del test en commit `dec7872`; el fallo de CI previo no es una aprobación.

**PENDIENTE:** controlador SYSTEM restaurador (copiar respaldo sellado, restituir XML exacto, reiniciar tarea, comprobar DNS e Internet), validación tras un reinicio verdadero en VM persistente y revalidación final del motor instalado en PC. El canal público del motor permanece apagado. La ejecución general #41366011021 estaba en progreso al último control; la prueba dirigida nueva sí aprobó.

**SIGUIENTE PASO:** integrar la operación concreta de restauración con estas precondiciones, ejecutar pruebas de interrupción/reinicio y no publicar el motor hasta cumplirlas.

## Continuación: restauración real de archivo faltante, sin habilitar producción

- [ed014d8](https://github.com/apdocentepba-hub/volve-updates/commit/ed014d8d7bc4f24a145de158d56894950545c86d): separación de admisión firmada `auditResidentSignedBootAdmissionLocked` para mantener **el mismo mutex protegido** entre verificación de Ed25519/respaldo/journal/motor y la operación posterior, evitando liberar y adquirir la exclusión a destiempo.
- [da94f2c](https://github.com/apdocentepba-hub/volve-updates/commit/da94f2c5a04734258481b61ee2d36c6691c96029): nueva primitiva **sin CLI de producción** `restoreSignedMissingOriginalWindows` para el caso específico de que el EXE original no exista. Exige sistema SYSTEM, clave editorial, firma, ACL, respaldos sellados, journal PENDING, inexistencia de motor y DNS53 inactivo bajo mismo mutex. Copia el backup a archivo temporal del mismo volumen, sincroniza, verifica SHA256, protege ACL y usa hardlink NTFS de creación exclusiva sin sobrescribir. Revisa nuevamente todos los elementos antes de publicar. No toca tareas, adaptadores, procesos, DNS ni publica recibo terminal.
- [beff1e7](https://github.com/apdocentepba-hub/volve-updates/commit/beff1e71098474bb6a806268647984cac01b6b54): ensayos Windows del restablecimiento de bytes, sin falsos `restored`, y rechazo frente a archivos desconocidos, snapshot adulterado, ausencia de SYSTEM, puerto53 ocupado, ACL defectuosa y cambio de estado en la segunda verificación.
- [982380e](https://github.com/apdocentepba-hub/volve-updates/commit/982380e0bd6044ab37f23f31bbf11c935e86ef14): workflow de Windows para ejecutar estas pruebas. **Ejecución exacta con tests nuevos:** [#41366793787](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41366793787). No usar resultados de #41366777208, que aprobó solamente con el estado anterior del test.
- Esta función todavía recibe verificadores internos inyectados y no está conectada a un SYSTEM watchdog productivo. Hace falta una envoltura de token SYSTEM real y ACL de nueva copia, completando después la importación de tarea XML, arranque de DNS y pruebas v4/v6 e Internet tras reboot. No implementar actualización productiva automáticamente basándose sólo en pruebas del archivo faltante.

## Resultado final de la recuperación por archivo original faltante (02/11/2026 UTC)

- Primera batería [#41366793787](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41366793787) **FAIL**: se detectó un error de alcance de variable en `os.Lstat` que confundía `ErrNotExist` con un error nulo. Ningún archivo fue restaurado en esa prueba de aprobación.
- Corregido mediante [80aa986](https://github.com/apdocentepba-hub/volve-updates/commit/80aa9861ac394d0b90e4671ee14fe1e54722369f), manteniendo la condición estricta de **archivo realmente inexistente**.
- **[Windows #41367221500](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41367221500) SUCCESS — los 6 tests nuevos PASS.** Verificación de restauración real del EXE original en fixture NTFS con SHA256 y permisos de respaldo, resultado idempotente sin falso `restored`, y rechazo de ejecutable distinto, token SYSTEM ausente, puerto 53 activo, respaldo adulterado, permiso NTFS imposible y actividad nueva detectada en segunda consulta.
- El código de restauración es un **componente real pero todavía independiente y no instalado**, no un recuperador de producción integrado. No implementa los casos de EXE candidato existente ni la importación/reinicio del XML de tarea SYSTEM, no verifica DNS después de un reboot y no habilita `releases/motor-stable.json`.

### Próximo tramo
Implementar la envoltura SYSTEM real (no inyectada), el driver de tarea original y la secuencia de recuperación de conectividad con recibos a prueba de corte. Ensayar el reinicio completo en VM persistente y luego revalidar la identidad del motor del usuario antes de autorizar migración. Centro estable 0.28.7 y canal de motor sin cambios.

## Tramo siguiente — restauración de tarea SYSTEM firmada (02/11/2026 UTC)

**REALIZADO:** [af69369](https://github.com/apdocentepba-hub/volve-updates/commit/af69369e3241d8f4661c21b5b08bd92bee225db8) agrega `restoreSignedOriginalSYSTEMTaskWindows`, una función **no expuesta como CLI ni activada en el launcher**. Requiere token SYSTEM, root canónico, firma editorial válida, journal pendiente, ACL verificadas, archivo EXE original intacto, XML original SHA-256 exacto y tarea quiescente (ningún motor ni puerto 53). Conserva el **mismo mutex global** durante dos auditorías completas y la importación de tarea desde el XML protegido. La operación rechaza tareas que apunten a ejecutables desconocidos, tiene revisión previa a `Register-ScheduledTask` y confirma después el SYSTEM/acción original. No altera DNS ni arranca motores ni escribe resultado terminal.
**PRUEBAS:** [747b976](https://github.com/apdocentepba-hub/volve-updates/commit/747b9769938717e1350f52bfea5c207bc06e28dc) añade tests de firma/journal/XML, original ausente/adulterado, token insuficiente, puerto53 activo, cambio entre inspecciones y respuesta ambigua del Scheduler. [CI Windows #41368116798](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41368116798) en ejecución al momento de redactar. **No llamar aprobado hasta resultado final**.
**LÍMITE:** los tests nuevos usan un ejecutor de Scheduler inyectado, no demuestran aún una importación real de tarea productiva bajo SYSTEM ni un reinicio. El piloto de restauración de tarea real en CI independiente ya había pasado con tarea desechable; falta integrar estas precondiciones y probar la secuencia completa.
**SIGUIENTE:** comprobar CI, implementar envoltura del watchdog productivo para SYSTEM y ejecutar ensayo en VM persistente con reboot de la tarea, DNS v4/v6 y conectividad, sin modificar el canal de motor.

## 01/11/2026 22:00 (Argentina) — Correcciones de restauración SYSTEM

- [CI #41368116798](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41368116798) **FAIL verificado**: el fixture del EXE anterior conservaba una DACL NTFS heredada y, correctamente, el restaurador rechazó `Inherited journal DACL`. La suite también alcanzó su timeout global de 7 minutos; no se consideró aprobación.
- [02fe8c3](https://github.com/apdocentepba-hub/volve-updates/commit/02fe8c35274d3b0e3c67e19d98041e739ecd8203): los tests ahora sellan la DACL del EXE anterior en el fixture NTFS **sin rebajar el verificador productivo**.
- [8b10266](https://github.com/apdocentepba-hub/volve-updates/commit/8b1026682d70749c69ebf8bd78ebb614d5016d66): separa las pruebas Windows de tarea firmada y regresión DNS/recuperación en dos invocaciones independientes; timeout de 8m y 9m respectivamente, total del job 24m.
- [14ae51f](https://github.com/apdocentepba-hub/volve-updates/commit/14ae51f6704896f6e8593cb30b50fec9daefa4a4): elimina el atajo de éxito si la tarea ya apunta al EXE original. Se reimporta el **XML completo y firmado** para recuperar los disparadores y ajustes; comprueba al finalizar que la tarea SYSTEM tiene la acción original, al menos un disparador y está habilitada.
- [CI #41370287439](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41370287439): batería correspondiente al último cambio, iniciada; **no declarar PASS antes de verificar `conclusion=success`**.
- La nueva función todavía utiliza ejecución inyectada para pruebas y no está conectada a un ejecutable productivo. Un sistema con DNS operativo debe permanecer intacto. Siguiente requisito: prueba como SYSTEM con una tarea descartable real usando permisos protegidos y recuperación DNS IPv4/IPv6 después del arranque; recuperación tras reboot persistente sigue pendiente.
