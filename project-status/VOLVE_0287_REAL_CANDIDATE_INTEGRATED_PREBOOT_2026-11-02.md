# VOLVÉ 0.28.7 — preparación integrada de candidato DNS REAL con rollback SYSTEM

Fecha 2026-11-02. Estado del resultado: **CI Windows SUCCESS, SIN REINICIO REAL**, no se publica release.

## REALIZADO
- `development/0.28.7/lab/vm_real_candidate_dns_rollback.ps1` (commit `799618d5269e754ef4502feee6b99739ae337252`), partiendo del laboratorio anterior ya comprobado en VM persistente.
- Compila y distingue DOS ejecutables reales Full DNS: original `VOLVE_CI_FreshDNS53.exe` y candidato `VOLVE_CI_Failing_Candidate.exe`. El candidato es Go `windows && volveci` con marca de linker y modo de laboratorio exclusivamente; NO es firmware ni motor de distribución.
- `Prepare` configura tarea original, catálogo Full CI 400005 líneas. `Arm` copia y fija hashes del candidato, almacena tarea XML original/plan protegido, instala watchdog SYSTEM AtStartup ANTES de cambiar tarea original.
- La nueva tarea candidata usa un trigger único a futuro en lugar de AtStartup para EVITAR competencia por UDP53 al reiniciar. La ejecución explícita SYSTEM verifica seis respuestas DNS reales IPv4/IPv6 y **termina con 83**. Se guarda constancia create-only de PID, SHA, six checks y el resultado LastTaskResult 83.
- El watchdog de arranque verificará recibos previo a reinicio, motor/archivos protegidos, importará el XML de tarea original e iniciará el motor Full CI y validará seis DNS antes de registrar recibo de recuperación. El verificador posreinicio exige eventos 118,100,201,102 correlacionados, PID SYSTEM, hash, dual-stack DNS y conectividad TCP IPv4; no declara firma productiva.
- Corregida condición de carrera: `Prepare` había detenido el motor pero Windows aún no liberaba su puerto UDP53. Se permite **únicamente espera pasiva acotada a 15 segundos** si el PID pertenece exactamente al motor original de laboratorio. Si es ajeno, inaccesible o sigue ocupado, aborta SIN matar procesos.
- README de uso solo en VM: `development/0.28.7/lab/VM_REAL_CANDIDATE_ROLLBACK.md`.

## COMPROBADO
- [CI Windows #41530730850](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41530730850) **SUCCESS**, commit `187dbb4cfb1807d369ab344aa4dc883603c0fec6`. Logs reales:
  - `PREPARED: isolated full-motor DNS trial ...; 400005 catalog lines; protected evidence.`
  - `ARMED: REAL Full CI DNS candidate ran 6/6 as SYSTEM then crashed with exit83; original motor preserved; watchdog registered.`
  - `PASS: real CI Full DNS candidate ran six dual-stack probes as SYSTEM and exited83; watchdog prearmed; fake reboot rejected`.
  - `PASS: 12 VM-only files: original + distinct real candidate + recovery scripts with SHA256 manifest, NOT product release`.
- Artefacto temporal (expira 2026-11-09): `VOLVE-0287-VM-REAL-CANDIDATE-ROLLBACK-NO-INSTALL`, GitHub artifact ID `13181257913`, 20.738.719 bytes, digest GitHub `sha256:a5a12d6e71b27f80222ec2a9b0ea652ec3ddf4a124f48d09c59ca2024a7a2e2c`.
- Prueba de candidato separado ejecutado anteriormente [#41528693726](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41528693726): SUCCESS, DNS 6/6 y salida 83.

## PENDIENTE (NO DECLARAR APROBADO)
- REINICIO REAL de VM persistente con este nuevo binario candidato y recuperación autónoma del motor Full CI. CI no reinicia su runner.
- Después, recuperación de ejecutable instalado 0.28.6 desde backup en un ensayo **firmado de punta a punta**, con atestación de permiso editorial y SHA-256 reales, validación DNS y conectividad, UI de actualización sin reinstalar y pruebas de interrupción.
- Ausencia de autorización para modificar host productivo o publicar `releases/motor-stable.json`.

La matriz de aceptación técnica productiva se mantiene **65/100**. El estado de protección Windows original y el Centro no cambia.
