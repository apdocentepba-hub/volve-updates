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
| L1 | Dependencia transitiva faltante, modificada o no resoluble | VM desechable con binarios legacy exactos | Rechazo antes de armar sustitución | Parcial: imports PE regulares (directorio 1) y delay-load (directorio 13) pasan fixtures en Windows y Ubuntu; los binarios legacy exactos y cargas dinámicas no fueron auditados. No acredita clausura completa. |
| L2 | Watchdog ausente, DACL no protegida o mutex ocupado | VM Windows | Rechazo sin cambiar motor ni tareas | Parcial: gates unitarios y E2E SYSTEM con tarea temporal aprobados; no prueba rechazo de todas las condiciones ni es controlador productivo |
| L3 | Interrupción tras preparar candidato y antes de commit | VM Windows | Journal pendiente y watchdog previamente armado | No aprobado: el E2E actual prueba rollback por fallo de conectividad después del switch, no una interrupción forzada entre preparación y commit |
| L4 | Recuperación automática después de reinicio real | VM Windows con reinicio real | Restauración exacta de tres tareas/acciones y journal `restored` | Pendiente |
| L5 | Preservación de DNS/HOSTS y tareas ajenas | VM Windows | Hashes/estado antes y después idénticos | No probado en este flujo |

## Evidencia parcial adicional — watchdog SYSTEM sin reboot

En el HEAD `09fdaa91107b019239af7613dc7bf96a8bacf7a0`, el workflow [43781873796](https://github.com/apdocentepba-hub/volve-updates/actions/runs/43781873796) pasó dos casos en Windows hospedado: commit de una tarea temporal y rollback por fallo de conectividad mediante un watchdog independiente registrado como SYSTEM. Los logs identifican los casos `signed-commit` y `SYSTEM-watchdog-rollback-on-connectivity-failure`.

La tarea y el driver son fixtures descartables; el fixture del test declara cobertura sintética para aislar la mecánica transaccional. El workflow no usa las tareas VOLVE instaladas, no cambia el DNS del host, no ejecuta el motor legacy real ni reinicia Windows. Esta repetición confirma solamente evidencia parcial del mecanismo de watchdog SYSTEM en L2; L1, L3, L4 y L5 siguen sin aprobarse.


## Antecedente de auditoría: sólo imports regulares (antes de ampliar a delay-load)

En el estado anterior de la PR #18 se incorporó lectura directa de la tabla PE de imports regulares (directorio 1), recorrido recursivo con SHA-256 por archivo y un resolvedor que busca únicamente en raíces explícitamente autorizadas. Rechaza DLLs sin coincidencia única, candidatos enlazados y raíces enlazadas. **El parser no procesa el directorio 13 de delay-load imports.** Por eso `StaticImportClosureComplete` significa solamente que se resolvieron los imports regulares que el parser ve; no equivale a que estén inventariadas todas las dependencias estáticas declaradas en PE. El resultado nunca marca dependencias de ejecución como certificadas.

En el HEAD `ab2f3be3c9e28d093729c14735dbfbcc827e4dc2), CI pasó en Windows y Ubuntu [la matriz de límites](https://github.com/apdocentepba-hub/volve-updates/actions/runs/43840330103), incluidos fixtures de resolución válida, coincidencia ambigua y rechazo de raíz enlazada. El [gate de cobertura](https://github.com/apdocentepba-hub/volve-updates/actions/runs/43840330131) también pasó.

Estas son pruebas sintéticas de parser/resolvedor. No se leyeron los binarios exactos del respaldo privado, no se resolvieron DLLs reales del motor, no se parseó el directorio PE 13 de imports delay-load, y no se inspeccionaron cargas dinámicas, COM, scripts ni resolución Side-by-Side/API-set. Por eso L1 sigue pendiente y el gate conserva `TransitiveDependenciesCertified=false`.


## Ampliación comprobada de la auditoría PE delay-load — 16/11/2026

- Implementado `ReadLegacyPEDelayImports` para el directorio PE 13, con descriptores de 32 bytes y `Attributes` 0 (VA antiguo con base de imagen) o 1 (RVA moderno). Se rechazan atributos reservados, directorios fuera de datos raw, terminadores ausentes o con datos posteriores, límites excesivos y nombres de DLL inseguros.
- `AuditLegacyPEStaticImportClosure` recorre ahora DLLs declaradas tanto en imports regulares como delay-load; cada archivo guarda listas separadas `Imports` y `DelayImports`, tamaño y SHA-256. Los duplicados se resuelven una vez. Una dependencia delay-load sin ruta única aprobada deja `StaticImportClosureComplete=false`.
- **CI PASS en runners GitHub Actions Windows y Ubuntu:** [boundary run 43978193914](https://github.com/apdocentepba-hub/volve-updates/actions/runs/43978193914), commit `e67ea979b9f29770b81d22f4f41e9a4d175b1e9d`. Ejecutó los nuevos tests `TestReadLegacyPEDelayImports*` (PE32/PE32+, VA, atributos reservados, límites, nombres y terminadores), `TestAuditLegacyPEStaticImportClosureIncludesDelayedTransitiveDLLs` y `TestAuditLegacyPEStaticImportClosureFailsClosedOnDelayedDLL`. La matriz de límites y los tests previos también pasaron.
- **Alcance:** se extrajeron nombres de DLL y se resolvieron rutas recursivas sólo en fixtures sintéticas. No se certifican funciones/thunks exportados, `LoadLibrary`, COM, SxS/API-set, código gestionado, scripts ni carga efectiva en Windows. No se incorporaron al laboratorio los binarios legacy exactos del respaldo privado. L1 sigue **PARCIAL** y `TransitiveDependenciesCertified=false`.
- **Bloqueos intactos:** L3–L5 y la prueba de reinicio real L4 no están aprobados. El gate no habilita instalación, sustitución, limpieza, merge ni release. No se modificó ninguna PC del usuario.

## Cierre de ventana pre-switch en el ensayo VM — 17/11/2026

- Antes, la secuencia `boot_recovery_lab.ps1 -Mode stage` reemplazaba la tarea temporal por un candidato **antes** de crear el watchdog SYSTEM. Se corrigió la secuencia: journal pendiente → registrar y verificar watchdog SYSTEM con trigger de arranque → reemplazar la tarea temporal → avanzar el journal. Si falla el armado del watchdog, el candidato no se sustituye.
- El recover ahora distingue dos estados seguros, comprobando la identidad SYSTEM y la acción exacta: original todavía intacto (no lo reescribe) o candidato temporal reconocido (restaura el XML protegido). Rechaza cualquier otra acción.
- Ensayo nuevo exclusivamente en runner Windows hospedado con tareas `VOLVE-CI-*`: inyección controlada de interrupción pre-switch, verificación de tarea original intacta, watchdog SYSTEM registrado, ejecución **manual** como SYSTEM y journal `NO_ROLLBACK:restored`. **PASS** en [CI 44075074583](https://github.com/apdocentepba-hub/volve-updates/actions/runs/44075074583), commit `12991b3529e0515fa9492312c73ebc4a15a1c3b3`. El mismo workflow compiló helper, verificó sintaxis PowerShell, rechazó Verify sin nuevo boot y empaquetó kit con SHA-256.
- Esta prueba cierra sólo la ventana de cobertura previa a la sustitución en el **fixture de laboratorio**. No demuestra caída forzada del proceso durante una migración productiva, no ejercita restauración de las tres tareas legacy, no verifica DNS/HOSTS del host y **no reinicia Windows**. L2 y L3 siguen parciales; L4 y L5 pendientes. `TransitiveDependenciesCertified=false`, `RecoveryAfterRebootVerified=false`; sin instalación, limpieza ni release.

## Verificación de integridad y XML exacto de tarea tras arranque — 17/11/2026

- El comando `vm_reboot_proof.ps1 -Mode Prepare` ya registra en `vm-trial.json`, además de las huellas del script y el helper, el SHA-256 independiente de `old-task.xml` y del binario **ficticio** `old-test-engine.bin`. El recibo se escribe después de armar el watchdog y crear ambos archivos. `-Mode Verify` rechaza modificaciones de cualquiera de los dos respaldos **antes de examinar el arranque**.
- El verificador de reinicio exige además comparar el XML de la tarea actualmente registrada (`Export-ScheduledTask`) con el XML original protegido, normalizando solamente la indentación interelemento mediante un lector XML con DTD deshabilitadas y límite de tamaño, sin descartar texto con espacios en campos hoja como `Arguments`. No basta con que la acción aparente ser `cmd.exe /C exit 0`: cualquier alteración de principal SYSTEM, acciones extra, argumentos, disparadores o permisos expresados en el XML rechaza la prueba. La salida de un reinicio real sólo podrá declarar `restoredTaskXMLMatchesProtectedSnapshot=true` después de esta comparación.
- **CI sintético PASS Windows** en [kit 44078148799](https://github.com/apdocentepba-hub/volve-updates/actions/runs/44078148799): los once casos adversarios de XML (acción, argumentos, principal, disparador, acción extra, RunLevel, namespace, DTD, XML inválido, exceso de tamaño y argumento con espacios frente a argumento vacío) se rechazaron. Además, CI alteró sucesivamente ambos archivos originales y comprobó el rechazo anticipado, restituyó los bytes y volvió a confirmar que no hubo reinicio genuino.
- **Sin extrapolación:** estas son pruebas de parser, integridad y tareas descartables sin reboot. No se ha ejecutado aún `Verify` con un arranque nuevo de una VM persistente ni se han auditado las tres tareas productivas y sus binarios exactos. La comparación XML después de una restauración real de Task Scheduler sigue pendiente de ensayo, y puede requerir ajustes de normalización sin relajar equivalencia. L4 continúa **NO APROBADO**; no se autoriza instalar, sustituir, limpiar, fusionar ni publicar.

## Integración real con Windows Task Scheduler y cierre del journal — 17/11/2026

- El workflow [44081197802](https://github.com/apdocentepba-hub/volve-updates/actions/runs/44081197802) ejecutó en Windows hospedado un escenario **post-switch ficticio**: sustitución de la acción de una única tarea `VOLVE-CI-*`, ejecución **manual** de watchdog independiente como SYSTEM, restauración por `Register-ScheduledTask -Xml`, nuevo `Export-ScheduledTask` y comparación del XML normalizado contra el respaldo original. **PASS** de la integración con el Task Scheduler real, no únicamente fixtures XML inventados.
- Como defensa adicional, el script `boot_recovery_lab.ps1` ahora **no escribe `restored` en el journal ni genera marcador de éxito hasta verificar dentro del proceso SYSTEM** que el XML completo de la tarea recién registrada coincide con el respaldo de laboratorio. Esto protege contra un registro de tarea que conserve la acción pero altere principal, disparadores o configuración.
- **CI PASS** del nuevo guard en [kit 44081485321](https://github.com/apdocentepba-hub/volve-updates/actions/runs/44081485321), commit `69d13b3dd944deae4e26be1a177126bcfd7c884a`. Los gates de cobertura y límites pasaron en ese commit. El E2E signed migration de ese mismo HEAD se consultó todavía en ejecución; no debe contarse como completado sin su resultado.
- **Limitación fundamental:** en ambos ensayos el watchdog SYSTEM fue disparado **manualmente**, y la tarea, el motor y el journal eran únicamente fixtures de CI. No hubo reinicio de Windows ni restauración de las tres tareas legacy exactas; por lo tanto L3/L4 siguen NO APROBADOS y `RecoveryAfterRebootVerified=false`. Este código no autoriza DNS, instalación, limpieza, merge ni release.

## Ensayo negativo del watchdog SYSTEM: acción original, trigger alterado — 17/11/2026

- El workflow [44086226478](https://github.com/apdocentepba-hub/volve-updates/actions/runs/44086226478) probó una **tarea real pero descartable** `VOLVE-CI-StartupMotor-*` en Windows CI: después de armar el journal y watchdog, reemplazó la tarea ficticia para que su acción volviera a ser `cmd.exe /C exit 0` pero cambió su disparador a otra fecha. Esto simula una definición parcialmente restaurada que puede superar una comprobación superficial de acciones.
- **PASS comprobado en logs:** la ejecución manual del watchdog como SYSTEM detectó diferencias del XML frente al respaldo intacto y reportó fallo; el journal permaneció `ROLLBACK_REQUIRED`, el marcador `boot-recovery-success.marker` no existió y la definición siguió siendo distinta. El mismo run verificó también la ruta positiva con restauración XML completa.
- **No hubo reboot real**, ni se tocaron tareas de VOLVÉ del usuario ni su motor DNS. Esto acredita el comportamiento *fail-closed* del verificador real de Windows Scheduler, pero no valida recuperación autónoma de las tres tareas legacy tras reinicio o los binarios exactos. Los criterios L3/L4 siguen pendientes; sin autorización de instalar/publicar.

## Evidencia previa que no alcanza

El laboratorio de reinicio de motor y DNS existente acredita persistencia del motor de CI y consultas DNS en su propio escenario. El reporte V4 declara `new_motor_migration_proven=false` y deja sin probar la restauración del ejecutable original y el XML de tarea tras interrumpir una migración. No satisface L1–L5.

## Salida exigida

El informe debe conservar run ID, commit, versión de Windows, identidad SYSTEM, boot time anterior/posterior, hashes de entrada/salida, estado del journal, resultado de cada fila L1–L5 y prueba de preservación DNS/HOSTS. No debe publicar rutas privadas, contenido DNS/HOSTS ni datos del respaldo local.

Hasta que L1–L5 tengan evidencia aprobada, `TransitiveDependenciesCertified=false` y `RecoveryAfterRebootVerified=false`; el gate de migración bloquea instalación, conmutación y limpieza.
