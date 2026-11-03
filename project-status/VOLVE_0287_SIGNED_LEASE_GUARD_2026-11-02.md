# VOLVÉ 0.28.7 — revisión del guardián de mutex de migración firmada

Fecha: 2026-11-02. Base: rama `feature/motor-updater-0287-pilot`, commit `c06bb3e4f852759f93cb2d812c97835b50ce46d4`.

## Hallazgo de seguridad

En `resident_protected_signed_switch_windows.go`, el adaptador incluía `SignedLegacySwitchDriver` de forma anónima. Eso dejaba accesibles operaciones delegadas (`Snapshot`, `InstallVersionedCandidate`, `Switch`, `Commit`, `Preflight`, `IndependentRecoveryReady` y `VerifyPreparedTarget`) sin una comprobación LOCAL de posesión del mutex Windows. El controlador de transacciones normalmente obtenía ese mutex, pero el adaptador en sí no impedía llamadas directas o erróneas a esos métodos.

Además, la función de liberación capturaba un puntero de adaptador mutable. Un callback de finalización antiguo podía, en principio, liberar el nuevo mutex retenido por una transacción posterior sobre la misma instancia.

## Corrección propuesta (PR no publicado)

- Se eliminó la interfaz anónima embebida, usando un delegado privado nombrado para que futuros métodos del contrato no se promocionen automáticamente sin verificación.
- Se interpusieron envoltorios a **todas** las operaciones del contrato de migración firmada. Rechazan invocaciones sin una sesión protegida de Windows activa.
- Se agregó `stateMu` para serializar finalizadores y métodos delegados, evitando soltar el mutex mientras un método del adaptador sigue ejecutándose.
- La devolución de `AcquireExclusiveMigration` se asocia a un número de sesión; un finalizador de una sesión anterior no afecta un bloqueo posterior.
- `Restore` libera el mutex de Windows durante la ejecución del watchdog independiente y lo vuelve a adquirir antes de permitir comprobaciones de salud; la exclusión local se mantiene durante el traspaso.
- Se añadieron regresiones negativas para **todos** los métodos sin lease y pruebas con mutex real Windows para liberación, reconexión y finalizador obsoleto.
- Se agregó un workflow limitado a runner Windows descartable y lectura de código; no contiene pasos de publicación, ni cambios de DNS ni tareas productivas.

## Estado de aceptación

**Código propuesto y CI Windows enfocada APROBADA; PR todavía sin integrar.** Esta modificación no incorpora un controlador OS completo para conmutar 0.28.6 → 0.28.7, ni sustituye la prueba de migración real firmada. No cambiar `releases/motor-stable.json`; no activar automáticamente el motor. El indicador de aceptación productiva permanece en **65/100** hasta superar su matriz de pruebas.

## Requisitos antes de integrar

1. Comprobar el workflow de Windows y regresiones sin bypass de mutex ni deadlock.
2. Inspeccionar `Restore` con falla y cancelación, y revisar que el wrapper no habilite operaciones sin permiso editorial.
3. Mantener bloqueado el cambio productivo de tarea DNS y ensayar migración real firmada en VM persistente con snapshot, conmutación/reinicio/rollback, DNS53 dual-stack y conectividad TCP.
4. Revisar y aprobar la integración a la rama piloto; el PR nunca debe fusionarse solo ni disparar despliegues.

## Evidencia final CI enfocada

- [GitHub Actions #41548175169](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41548175169) completada con **SUCCESS** sobre commit `d02886f7b86a72713878cf1e92b8ad90b5a14655`.
- Reconstrucción de fuentes desde ZIP SHA-256 fijado y dos overlays con huellas verificadas: **PASS**.
- Pruebas `go test ./motorupdate -run '^TestProtectedSigned' -count=1 -timeout 10m -v`: **PASS**, incluidas negativas de 10 operaciones sin mutex, finalizadores obsoletos, handoff/reacquisición y la carrera entre finalizador y `Switch` en curso.
- `go vet ./motorupdate`: **PASS**.
- El run anterior #41547867800 también fue **SUCCESS**; #41548091997 se canceló por una nueva revisión, no es evidencia de fallo.
- Este CI específico no ejercita el cambio DNS real, no instala un motor nuevo y no prueba aún recuperación firmada tras reboot; mantiene `motor-stable.json` ausente y el progreso en **65/100**.


## 03/11/2026 — Cierre completo de la batería previa y nuevo límite criptográfico

- [Windows run #41555207181](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41555207181): **SUCCESS, 13 de 13 trabajos** sobre commit `76c7c32a9bc3a9ea19d66f0d76167c9f32915e0d`. Un job `motorupdate` y 12 particiones disjuntas de watchdog; ya no queda un timeout sin atribuir de esa ejecución.
- Los logs de `windows-protected-lease` confirman el paso de `TestProtectedBootRefusesUnleasedOriginalOperations`, `TestProtectedBootLeaseGatesVerifyRestoreAndRejectsStaleFinalizer`, `TestProtectedBootFinalizerWaitsForOriginalRestore`, `TestProtectedSignedFullTransactionCommitAndRecoveryUnderNativeMutex` en commit/fallo/cancelación, y el paquete completo `motorupdate`.
- Hallazgo posterior de auditoría: los dos adaptadores externos `publisherBoundResidentBootDriver` y `durablePublisherBootDriver` realizaban **lecturas de permiso editorial/journal/ACL antes de entrar al chequeo de lease del adaptador interno**. Aunque las operaciones finales ya rechazaban ejecución sin mutex, podía haber un intervalo donde se leyera y verificara material criptográfico sin exclusión de otro proceso.
- Corrección propuesta: las dos capas externas ahora invocan `protectedResidentBootDriver.underProtectedLease` **antes** de leer/verificar evidencia y retienen ese mismo lease durante la verificación y la operación privilegiada; evitan abrir una ventana entre validar el respaldo y verificar/restaurar el original.
- Pruebas añadidas: `TestPublisherBoundBootEvidenceRequiresLeaseBeforeAnyACLReader`, `TestPublisherBoundBootFinalizerWaitsForSignedEvidence`, `TestDurablePublisherBootEvidenceRequiresLeaseBeforeDiskRead`. La comprobación del pipeline exige la presencia de los tres tests en la reconstrucción y los ejecuta sobre Windows hospedado, sin DNS productivo.
- **Estado de esa nueva revisión:** [run #41557592889](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41557592889), commit `25430b592382c4a7711a3e20ef802764ff756fdb`, **pendiente/en ejecución** al registrar esto. No confundir el éxito del commit anterior con la aprobación de este cambio.
- El PR #3 sigue en **DRAFT**, no fusionado. No se modificó `main`, el canal del motor, el DNS de una instalación ni la PC del usuario.

**Control de aceptación:** 65/100 para el componente de actualización Windows. La liberación del motor 0.28.7 sigue **NO AUTORIZADA** hasta una migración firmada de 0.28.6, controlador real, copia NTFS, recuperación SYSTEM y reinicio de Windows en una VM persistente, con pruebas DNS 53 de ambas familias y conectividad externa.
