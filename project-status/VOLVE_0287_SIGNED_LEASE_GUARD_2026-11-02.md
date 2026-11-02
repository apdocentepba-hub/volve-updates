# VOLVÉ 0.28.7 — revisión del guardián de mutex de migración firmada

Fecha: 2026-11-02. Base: rama `feature/motor-updater-0287-pilot`, commit `c06bb3e4f852759f93cb2d812c97835b50ce46d4`.

## Hallazgo de seguridad

En `resident_protected_signed_switch_windows.go`, el adaptador incluía `SignedLegacySwitchDriver` de forma anónima. Eso dejaba accesibles operaciones delegadas (`Snapshot`, `InstallVersionedCandidate`, `Switch`, `Commit`, `Preflight`, `IndependentRecoveryReady` y `VerifyPreparedTarget`) sin una comprobación LOCAL de posesión del mutex Windows. El controlador de transacciones normalmente obtenía ese mutex, pero el adaptador en sí no impedía llamadas directas o erróneas a esos métodos.

Además, la función de liberación capturaba un puntero de adaptador mutable. Un callback de finalización antiguo podía, en principio, liberar el nuevo mutex retenido por una transacción posterior sobre la misma instancia.

## Corrección propuesta (PR no publicado)

- Se interpusieron envoltorios a **todas** las operaciones del contrato de migración firmada. Rechazan invocaciones sin una sesión protegida de Windows activa.
- Se agregó `stateMu` para serializar finalizadores y métodos delegados, evitando soltar el mutex mientras un método del adaptador sigue ejecutándose.
- La devolución de `AcquireExclusiveMigration` se asocia a un número de sesión; un finalizador de una sesión anterior no afecta un bloqueo posterior.
- `Restore` libera el mutex de Windows durante la ejecución del watchdog independiente y lo vuelve a adquirir antes de permitir comprobaciones de salud; la exclusión local se mantiene durante el traspaso.
- Se añadieron regresiones negativas para **todos** los métodos sin lease y pruebas con mutex real Windows para liberación, reconexión y finalizador obsoleto.
- Se agregó un workflow limitado a runner Windows descartable y lectura de código; no contiene pasos de publicación, ni cambios de DNS ni tareas productivas.

## Estado de aceptación

**Código propuesto, revisión y CI pendientes.** Esta modificación no incorpora un controlador OS completo para conmutar 0.28.6 → 0.28.7, ni sustituye la prueba de migración real firmada. No cambiar `releases/motor-stable.json`; no activar automáticamente el motor. El indicador de aceptación productiva permanece en **65/100** hasta superar su matriz de pruebas.

## Requisitos antes de integrar

1. Comprobar el workflow de Windows y regresiones sin bypass de mutex ni deadlock.
2. Inspeccionar `Restore` con falla y cancelación, y revisar que el wrapper no habilite operaciones sin permiso editorial.
3. Mantener bloqueado el cambio productivo de tarea DNS y ensayar migración real firmada en VM persistente con snapshot, conmutación/reinicio/rollback, DNS53 dual-stack y conectividad TCP.
4. Revisar y aprobar la integración a la rama piloto; el PR nunca debe fusionarse solo ni disparar despliegues.
