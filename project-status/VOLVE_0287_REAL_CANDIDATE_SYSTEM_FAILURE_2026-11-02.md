# VOLVÉ 0.28.7 — candidato ejecutable real con falla controlada, Windows CI
Fecha: 2026-11-02. Rama: `feature/motor-updater-0287-pilot`.

## REALIZADO
- Se agregó el módulo condicionado a build tags `windows && volveci`: `development/0.28.7/inapp/ci_failing_candidate_dns53_windows.go`.
- El nuevo modo `--ci-failing-candidate-dns53` requiere VM detectada, ruta exclusiva de laboratorio, token de laboratorio, SID real SYSTEM, catálogo Full CI intacto (400.005 reglas de prueba) y una **segunda compilación diferenciada** por el enlace `ciCandidateBuildIdentity=VOLVE-0287-VM-FAIL-CANDIDATE`. Las compilaciones ordinarias del motor CI no habilitan ese fallo.
- Ese motor de prueba ejecuta el servicio DNS real de producción en loopback y valida respuestas para tres dominios por IPv4 y tres por IPv6; sólo entonces escribe evidencia con SHA-256 del binario, PID, seis resultados y carácter NO firmado. Termina intencionalmente con `os.Exit(83)` (sin conmutación/restauración de tareas).
- Se agregó workflow independiente `.github/workflows/volve-0287-real-candidate-crash-system-ci.yml` con VM efímera Windows y tareas SISTEMA descartables; después de ejecutar el candidato exige `LastTaskResult=83`, prueba del motor 6/6 y ausencia de ocupación residual de UDP53 dual-stack, DNS del adaptador sin modificar y limpieza de la tarea de ensayo.

## COMPROBADO
- [GitHub Actions #41528693726](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41528693726): **SUCCESS**, commit `794071e331e65a42f8c6c92f88ef2939268d5d8e`.
- Log de ejecución: `PASS: CI-only Full DNS catalog created and verified before SYSTEM task startup`.
- Log final: `PASS: ACTUAL complete VOLVE DNS engine as SYSTEM answered 6/6 IPv4/IPv6, then its DISTINCT lab EXE exited with 83 and released DNS53`.

## PENDIENTE
- Ensayar ESTE ejecutable candidato diferenciado en VM Hyper-V persistente y demostrar watchdog SYSTEM que restaura el motor Full CI anterior **después de un reinicio real**. El ensayo anterior de esa recuperación se hizo con candidato ficticio `cmd.exe /C exit 83`.
- Integrar binario y autorización editorial PRODUCTIVOS firmados con rescate de la instalación real 0.28.6, con aprobación específica antes de modificar el host. El modo de falla CI no pertenece a un motor firmado/publicable.
- Revalidación de motor/permiso vigente en equipo, transición, protección DNS/Internet y liberación segura del canal.

**Puntuación de aceptación productiva:** `65/100` sin cambios. Un candidato de CI ejecutado no sustituye el criterio de migración real y firmada.
