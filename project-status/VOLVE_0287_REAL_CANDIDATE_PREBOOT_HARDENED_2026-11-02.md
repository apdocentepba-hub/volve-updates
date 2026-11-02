# VOLVÉ 0.28.7 — candidato DNS REAL y rollback SYSTEM, preboot reforzado

Fecha: 2026-11-02. Todo el trabajo está en rama piloto, sin release ni modificación de host.

## REALIZADO
- Se robusteció el recuperador de laboratorio `vm_real_candidate_dns_rollback.ps1` para impedir `Cleanup` antes de `Verify` posterior a reinicio real. El limpiador comprueba evidencia persistente del watchdog, tarea, GUID de eventos, SHA-256 del motor anterior, catálogo, candidato y recibos, 6/6 DNS, conectividad y `signedProductionMigrationProven=false`; aborta sin retirar tareas si falta evidencia.
- Se permite limpiar más tarde aunque el motor DNS de CI finalice naturalmente por su límite de ejecución a los 30 minutos; si aún está en ejecución se confirma identidad SYSTEM y UDP53 del motor correcto.
- Se añadieron **tres pruebas negativas** en Windows CI: impedir `Verify` con falso reinicio, impedir `Cleanup` sin reinicio/evidencia y rechazar `Recover` con token distinto de SYSTEM.
- La compilación integra **dos binarios reales diferentes** de motor DNS de laboratorio: original conservado y candidato Full CI cuya ejecución bajo SYSTEM prueba DNS IPv4/IPv6 6/6 antes de salir con código 83. El watchdog independiente queda armado solo en tareas descartables; la prueba CI jamás reinicia el SO anfitrión.

## COMPROBADO
- [CI #41534999967](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41534999967): SUCCESS con logs `PASS: false boot, premature cleanup and manual non-SYSTEM recovery all rejected`.
- [CI #41535141744](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41535141744): **SUCCESS** sobre commit `af87d1705b7a0e8289bfeefb71f25f9d79c1aa0a`, incluyendo la última corrección de limpieza posterior al vencimiento de 30 minutos; compilación, preparación, seis DNS candidatos, fallo83, prearmado de watchdog y test negativos aprobados; empaquetado SHA-256 aprobado.
- Artefacto final de laboratorio de esta tanda: `VOLVE-0287-VM-REAL-CANDIDATE-ROLLBACK-NO-INSTALL`, ID `13183347475`, tamaño `20.739.176` bytes, digest GitHub `sha256:a3322719812c6465e0ce1afb0b578d6fe5951d0cf005efba12a83b0be642c272`, expira 2026-11-09.

## PENDIENTE
1. En `VOLVE-LAB-0287`, snapshot antes de ensayo `ANTES-CANDIDATO-REAL-0287`; extraer **este** artefacto, ejecutar `Probe → Prepare → Arm`, reiniciar exclusivamente la VM, ejecutar `Verify` y auditar `real-candidate-rollback-proof.json`; `Cleanup` después del JSON aprobado. La versión con hash de artefacto anterior quedó superada por esta entrega reforzada.
2. Puente **productivo firmado** del motor real 0.28.6 a 0.28.7 con respaldo, mutex, permiso editorial, comprobación de DNS/Internet, revalidación del EXE local y autorización del usuario. La prueba CI no toca su host, no cambia DNS de adaptadores y no publica `motor-stable.json`.
3. Suite general de Windows para la rama final en curso; la aprobación dirigida de este laboratorio no equivale a un global PASS.

**Aceptación técnica productiva del actualizador: 65/100, sin cambios.** Este hito es una prueba integrada pre-reinicio con un ejecutable real de laboratorio, NO actualización productiva ni recuperación post-reinicio de este nuevo binario.
