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
