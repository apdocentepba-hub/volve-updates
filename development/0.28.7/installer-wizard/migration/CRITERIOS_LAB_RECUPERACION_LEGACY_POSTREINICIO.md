# Criterios del laboratorio de recuperación legacy tras reinicio

**Estado:** especificación de aceptación; todavía no acredita que la prueba se haya ejecutado.  
**Alcance:** recuperación de la migración Windows de VOLVÉ 0.10.2 en una VM desechable.  
**Prohibido:** ejecutar este ensayo en la PC del usuario, modificar DNS/HOSTS del host o retirar tareas productivas.

## Qué debe demostrar la prueba

1. Los artefactos originales exactos del caso de laboratorio quedan ligados a un manifiesto privado con ruta, tamaño y SHA-256. Deben incluir las tres definiciones XML SYSTEM, las acciones directas y cada dependencia declarada por el verificador. Una dependencia no resuelta deja el resultado en **NO APROBADO**.
2. La configuración de prueba se arma dentro de una VM identificada positivamente y con checkpoint previo. Las tareas usan nombres temporales exclusivos del ensayo; no se reutilizan nombres productivos.
3. Antes de cualquier sustitución existe un watchdog independiente SYSTEM con disparador de inicio, journal durable y copia protegida del estado original. El estado del watchdog y sus rutas se vuelve a verificar bajo el mutex compartido.
4. El ensayo interrumpe deliberadamente la transacción después de registrar el estado candidato y antes del commit. No alcanza con iniciar el watchdog manualmente.
5. La VM se reinicia de verdad. La prueba exige que `Win32_OperatingSystem.LastBootUpTime` avance, que el proceso de recuperación corra como SID `S-1-5-18` y que los eventos de Task Scheduler correspondan a la misma instancia de ejecución posterior al nuevo arranque.
6. Después del reinicio se comparan las tres tareas restauradas con el XML original normalizado y con los hashes de acciones/dependencias; el journal debe terminar en `restored`. Una restauración parcial, duplicada o ambigua falla.
7. La auditoría antes/después confirma que DNS, HOSTS y tareas fuera del espacio temporal del ensayo no cambiaron.
8. La limpieza del ensayo solo retira los recursos con el identificador temporal validado y conserva los recibos como evidencia hasta que se deseche el checkpoint/VM.

## Matriz de evidencia

| ID | Escenario | Entorno requerido | Resultado esperado | Estado actual |
|---|---|---|---|---|
| L1 | Dependencia transitiva faltante, modificada o no resoluble | VM desechable con binarios legacy exactos | Rechazo antes de armar sustitución | No probado con los binarios legacy exactos |
| L2 | Watchdog ausente, DACL no protegida o mutex ocupado | VM Windows | Rechazo sin cambiar motor ni tareas | Parcial: gates unitarios y E2E SYSTEM con tarea temporal aprobados; no prueba rechazo de todas las condiciones ni es controlador productivo |
| L3 | Interrupción tras preparar candidato y antes de commit | VM Windows | Journal pendiente y watchdog previamente armado | No aprobado: el E2E actual prueba rollback por fallo de conectividad después del switch, no una interrupción forzada entre preparación y commit |
| L4 | Recuperación automática después de reinicio real | VM Windows con reinicio real | Restauración exacta de tres tareas/acciones y journal `restored` | Pendiente |
| L5 | Preservación de DNS/HOSTS y tareas ajenas | VM Windows | Hashes/estado antes y después idénticos | No probado en este flujo |

## Evidencia parcial adicional — watchdog SYSTEM sin reboot

En el HEAD `09fdaa91107b019239af7613dc7bf96a8bacf7a0`, el workflow [43781873796](https://github.com/apdocentepba-hub/volve-updates/actions/runs/43781873796) pasó dos casos en Windows hospedado: commit de una tarea temporal y rollback por fallo de conectividad mediante un watchdog independiente registrado como SYSTEM. Los logs identifican los casos `signed-commit` y `SYSTEM-watchdog-rollback-on-connectivity-failure`.

La tarea y el driver son fixtures descartables; el fixture del test declara cobertura sintética para aislar la mecánica transaccional. El workflow no usa las tareas VOLVE instaladas, no cambia el DNS del host, no ejecuta el motor legacy real ni reinicia Windows. Esta repetición confirma solamente evidencia parcial del mecanismo de watchdog SYSTEM en L2; L1, L3, L4 y L5 siguen sin aprobarse.

## Evidencia previa que no alcanza

El laboratorio de reinicio de motor y DNS existente acredita persistencia del motor de CI y consultas DNS en su propio escenario. El reporte V4 declara `new_motor_migration_proven=false` y deja sin probar la restauración del ejecutable original y el XML de tarea tras interrumpir una migración. No satisface L1–L5.

## Salida exigida

El informe debe conservar run ID, commit, versión de Windows, identidad SYSTEM, boot time anterior/posterior, hashes de entrada/salida, estado del journal, resultado de cada fila L1–L5 y prueba de preservación DNS/HOSTS. No debe publicar rutas privadas, contenido DNS/HOSTS ni datos del respaldo local.

Hasta que L1–L5 tengan evidencia aprobada, `TransitiveDependenciesCertified=false` y `RecoveryAfterRebootVerified=false`; el gate de migración bloquea instalación, conmutación y limpieza.
