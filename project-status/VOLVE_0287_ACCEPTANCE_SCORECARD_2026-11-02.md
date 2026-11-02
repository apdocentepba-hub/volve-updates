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
