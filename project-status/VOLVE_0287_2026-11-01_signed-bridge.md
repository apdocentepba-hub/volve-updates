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
