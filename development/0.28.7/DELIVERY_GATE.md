# VOLVÉ — control de entrega (30/10/2026)

## Propósito y prioridades

**Objetivo de usuario:** pasar una sola vez de la instalación 0.28.6 a un Centro y motor DNS que se actualicen desde **Actualizar VOLVÉ** (o automáticamente, una vez habilitado), sin descargar instaladores cada vez. Mantener bloqueos, DNS, recuperación ante interrupciones y persistencia de reinicio; evitar compras/suscripciones nuevas y no crear automatizaciones de ChatGPT. Una versión piloto con tests verdes NO equivale a producto entregado.

**Estado verificado:** 0.28.7 está en la rama `feature/motor-updater-0287-pilot`, no en el canal productivo. 0.28.6 ya está publicada como [pre-release](https://github.com/apdocentepba-hub/volve-updates/releases/tag/v0.28.6) y `main/releases/stable.json` apunta a ella. A 30/10/2026 **no existe** `main/releases/motor-stable.json`; no hay paquete motor estable y firmado anunciado.

## Evidencia aprobada en CI

- [GitHub Actions #41049825576](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41049825576): motor DNS con 400.002 dominios de prueba, puerto real 53 y consultas IPv4/IPv6 en Windows efímero, sin cambiar adaptadores.
- [GitHub Actions #41057083973](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41057083973): EXE real del Centro firmado con **clave efímera de laboratorio**, ejecutado bajo tarea SYSTEM aislada y restauración por otro ejecutable SYSTEM.
- [GitHub Actions #41061225944](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41061225944): correlación de eventos de arranque de Windows, rechazo de 12 falsos positivos; **no reinició realmente** la VM.
- [GitHub Actions #41062505590](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41062505590): 3/3 trabajos aprobados, chequeo de migración integrado al botón nativo, diagnóstico de firma/versión/compatibilidad/rescate sin modificar el DNS.

## Qué hace el Centro de desarrollo

1. Revisa los canales firmados de Centro y motor con el botón existente.
2. Si hay paquete DNS firmado compatible, lo descarga y verifica, sin activarlo.
3. **Nuevo:** explica directamente en el botón por qué el paquete no se puede instalar: constancia del motor heredado ausente, firma adulterada, Centro incompatible, falta de privilegios o preflight de DNS y rescate fallido. Ninguna de esas comprobaciones altera una tarea SYSTEM ni una regla.
4. No inventa éxito; informa siempre que el cambio productivo sigue bloqueado.

## Avance verificado: respaldo local del motor heredado sin reinstalación

**Código agregado al piloto**: `inapp/legacy_recovery_snapshot.go` y `inapp/legacy_recovery_windows.go`, con pruebas de unidad y Windows. La operación **explícita y privilegiada** `--prepare-legacy-rollback` invoca el preflight vigente (motor y tarea SYSTEM exactos, rescate y journal, DNS IPv4/IPv6), exporta y comprueba el XML real de la tarea, y guarda una copia exacta del ejecutable **sin atribuirle una versión histórica no verificada**. Crea un directorio de recuperación con ACL estricta SYSTEM/Administradores usando la DACL nativa de Windows, preserva SHA-256/tamaño de ejecutable y XML, y rehúsa sobrescribir respaldos. `--verify-legacy-rollback` inspecciona el backup sin conmutar nada. Ambas acciones exigen administrador. El botón público **todavía no dispara** la preparación ni instala el motor; el mecanismo solo está incorporado al piloto.

**Evidencia comprobada:** [Actions #41065924059](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41065924059): **3/3 trabajos aprobados**. El test real `TestWindowsProtectedLocalLegacyRollbackBackup` pasó (4,78 s) con permisos NTFS protegidos, ejecutable y XML respaldados, y original intacto. Pruebas negativas de respaldo alterado, XML modificado, destino existente, vínculos, ACL insuficiente y cancelación aprobadas. Se corrigió durante la ejecución un problema de CLIXML de PowerShell y un ACL residual del usuario del runner **sin eliminar el control de permisos**.

**No confundir:** esto **no** certifica el editor ni la versión del motor viejo, ni demuestra la reversión tras un cambio de motor o reinicio. Permite conservar los bytes originales para el rollback en una migración futura. Para eliminar el requisito de atestación de versión histórica y permitir el reemplazo hacen falta un **permiso de migración firmado por el editor que identifique explícitamente el SHA-256 del motor heredado y el motor destino**, el watchdog productivo y el ensayo de reinicio real. Firma del candidato nuevo obligatoria. No generar automáticamente un permiso ficticio con la clave efímera de CI.

## Paso 2: autorización firmada para migrar desde una instalación heredada sin versión acreditada

Se implementó el módulo **`motorupdate/legacy_migration_permit.go`** (solo verificador, sin conmutación). El editor puede firmar con su **misma clave de publicación Ed25519** un permiso JSON `dns-engine-legacy-migration` de alcance exacto: SHA-256/tamaño del ejecutable antiguo, tarea SYSTEM y argumentos esperados, SHA-256 del XML de recuperación, versión/SHA-256/tamaño del ejecutable nuevo, versión mínima del Centro y período acotado de validez.

El verificador exige conjuntamente: 1) firma del permiso con la clave fijada; 2) manifiesto y ejecutable **nuevo** firmados con la misma clave; 3) respaldo local anterior completo y protegido por ACL, que coincida en hash y tamaño con el permiso; 4) preflight real del motor SYSTEM/rescate/DNS y bytes instalados idénticos a los autorizados; 5) panel compatible y destino del primer ciclo de actualización (0.28.7 o posterior); 6) ausencia de inventario de un motor moderno ya registrado, para impedir reutilizar el puente heredado. **No se inventa una versión para el motor anterior**. Un recibo de respaldo local jamás suplanta la firma editorial ni autoriza un cambio de motor.

Se añadió `legacy_migration_permit_test.go` con casos de firma falsa, identidad y argumentos falsificados, huellas antiguas/nuevas cambiadas, respaldo adulterado o ausente, motor activo modificado, permiso expirado, destino antiguo, Centro incompatible, inventario moderno presente y preflight/ACL inseguros. **El código de esta subetapa todavía no integra la conmutación productiva ni publica un permiso real**. Firmas de laboratorio en tests son efímeras: no atribuirles autorización real del editor. Para uso en 0.28.6 habrá que generar, firmar y distribuir el permiso auténtico para **el hash exacto de la instalación a migrar**, sin exponer ni sustituir la clave privada.

## Paso 2 — integración de diagnóstico de permiso firmado en «Actualizar VOLVÉ» (30/10/2026)

**Código de piloto agregado, sin despliegue:** el Centro ahora busca un par opcional `<motor-staged>.migration.json` y `<motor-staged>.migration.sig` junto al ejecutable de motor previamente descargado y firmado. Si ninguno existe, mantiene el diagnóstico anterior de atestación heredada; si aparece uno solo o son inaccesibles, **bloquea** esa vía y nunca permite un fallback silencioso. Si están ambos, el diagnóstico privilegiado exige: firma Ed25519 real del editor, manifest/candidato del mismo editor, huella del ejecutable heredado y del XML de respaldo, respaldo intacto, ACL del directorio padre y del respaldo, tarea SYSTEM/rescate/DNS en preflight y compatibilidad del Centro. Ante cualquier error informa que **no instaló** nada. Sin elevación, el botón solo informa las comprobaciones pendientes; no abre UAC para un diagnóstico. El estado satisfactorio **no autoriza conmutar** el motor.

**Archivos:** `inapp/legacy_migration_status_windows.go`, `inapp/legacy_migration_status_windows_test.go`; enlace agregado en `inapp/motor_migration_status_windows.go`, overlay de compilación y job CI Windows. La rama sigue siendo un piloto; no hay un permiso de producción publicado ni distribución automática de los dos nuevos archivos. El botón de 0.28.6 instalado en una computadora real **no ha sido actualizado** con estos cambios de laboratorio.

**Calidad y límites:** las pruebas nuevas comprueban autorización firmada válida de laboratorio, ausencia/incompletitud, falsificación, clave equivocada, motor antiguo o backup adulterados, ACL insegura, preflight ausente/fallido, usuario sin privilegios, Centro incompatible, cancelación y conexión real al diagnóstico del botón. La firma de pruebas usa una clave Ed25519 **efímera** y jamás equivale a la del editor. La auditoría del propietario/DACL del árbol de recuperación completo, watchdog productivo, reinicio real de una VM persistente, verificación DNS tras reinicio y publicación del permiso auténtico siguen pendientes. No publicar automáticamente `motor-stable.json`, no cambiar claves, ni afirmar actualización del motor hasta satisfacer estos requisitos.

## Paso 2 — permisos del respaldo y transacción firmada heredada (continuación)

**Integridad NTFS ampliada:** `checkLegacyRecoveryACL` audita no solo la carpeta de respaldo sino las DACL de sus entradas inmediatas: ejecutable anterior, XML de la tarea y recibo. Rechaza vínculos, archivos especiales, entradas inesperadas y ACE de acceso de identidades ajenas a SYSTEM/Administradores. La verificación independiente `--verify-legacy-rollback` comprueba ahora también la carpeta padre y exige que `legacy-engine-recovery` tenga su DACL protegida de la herencia. El conjunto anterior de cambios de auditoría de archivos pasó 3/3 trabajos en [CI #41071198307](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41071198307). El chequeo adicional de herencia del directorio padre aún debe evaluarse en la nueva ejecución.

**Lógica transaccional heredada, aislada del uso productivo:** `inapp/legacy_managed_transaction.go` define `ApplySignedLegacyWithRollback` y `SignedLegacySwitchDriver`. A diferencia de `ApplyManagedWithRollback`, acepta un origen sin versión antigua registrada **solo con permiso editorial Ed25519 exacto**, respaldo local completo y preflight. Exige que un watchdog independiente ya esté preparado ANTES de crear/modificar archivos, y después de preparar el candidato exige **una segunda verificación** de identidad firmada, resguardo y watchdog antes de conmutar. Una falla posterior a la instantánea dispara intento de rollback bajo contexto independiente y chequeos de DNS local e Internet. Los ensayos falsifican fallas de firma, ACL, preflight, watchdog inicial/segundo, bytes antiguos/candidatos modificados, cancelación, conmutación, DNS e Internet.

**Límite decisivo:** todavía **no hay adaptador Windows productivo** que implemente el contrato y conmute la tarea real; el watchdog existente trabaja solo con tareas CI. Tampoco hay firma auténtica de migración distribuida, protección demostrada contra cambio de bytes entre el último chequeo y el switch, ni ensayo de reinicio real de VM persistente. El módulo es un contrato de ejecución y pruebas con dobles de laboratorio, NO una actualización aplicada. La 0.28.6 de usuario y el canal estable siguen intactos.

## Bloqueos reales para cumplir el objetivo

1. **Migración heredada sin fricción:** determinar una forma segura de identificar y respaldar el motor instalado 0.28.6. El código actual exige atestación firmada del motor heredado que **no está publicada**. Evaluar si una migración única con instantánea SHA-256, preflight DNS/conectividad, tareas verificadas, copia versionada y rollback independiente puede evitar exigir firma de la versión antigua, **sin** rebajar la firma obligatoria del motor nuevo ni habilitar un downgrade.
2. **Watchdog productivo:** el binario independiente actual solo acepta nombres `VOLVE-CI-*`; no es todavía un recuperador productivo para `VOLVE-DNS-SERVER-0270`. Implementar un componente productivo con identidad exacta, journal con ACL resistente a modificaciones, rollback del binario/tarea y comprobación DNS/Internet. Mantener el bloqueo duro del cambio hasta aprobarlo.
3. **Reinicio persistente real:** ensayar `Prepare -> reinicio -> Verify` en la **misma** VM Windows persistente, y además probar el motor real servido en el puerto 53 después del arranque. No llamar «reboot probado» a un relanzamiento manual del watchdog.
4. **Distribución firmada:** publicar paquete motor firmado por la **clave de publicación actualmente fijada**, `motor-stable.json` y su firma, solo después de aprobar recuperación. La firma de las pruebas de GitHub es efímera y NO puede reemplazar esa clave. Evitar modificar claves actuales sin autorización.
5. **Actualizador desde la instalación real:** migración 0.28.6 -> siguiente Centro + motor, sin desinstalar, sin romper DNS; probar también falta de Internet, archivos adulterados, cancelación, múltiples versiones y recuperación tras fallo.

## Política de entrega

NO publicar un instalador definitivo, no anunciar motor autopublicado, no borrar/restaurar instalaciones de terceros, no crear tareas ChatGPT, no modificar `main/releases/stable.json` ni añadir `motor-stable.json` hasta cumplir las condiciones anteriores. Continuar sobre la misma rama y priorizar una ruta segura hacia el cambio productivo, no generar versiones parciales por cada prueba.

**Siguiente avance sugerido:** construir un plan de migración local que conserve una huella/backup del motor heredado realmente funcional sin obligar al usuario a reinstalar para obtener una atestación histórica; definir y probar su control transaccional sin habilitar todavía la tarea productiva.
