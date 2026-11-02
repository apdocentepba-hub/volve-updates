# VOLVÉ 0.28.7 — laboratorio integrado cerrado y suite general aprobada

Fecha: 2026-11-02 (Argentina).

## Evidencia VM persistente
El usuario confirmó las salidas de consola de `vm_integrated_real_dns_rollback.ps1`:
- `Verify -LabId 20261102000301`: PASS — reinicio de Windows real; watchdog SYSTEM restauró motor DNS Full CI; IPv4/IPv6 6/6 y conectividad TCP.
- Se recibió y auditó el comprobante `integrated-rollback-proof.json`: GUID de la instancia, eventos 118/100/201/102, resultado 0, PID del motor y hashes declarados.
- `Cleanup -LabId 20261102000301`: `CLEAN: only two disposable integrated VM tasks removed; all protected evidence retained.`

**Laboratorio cerrado, sin tareas descartables del tercer ensayo.** La VM puede apagarse sin repetir ensayos.

## Pruebas generales del piloto
[GitHub Actions #41518980701](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41518980701), head `7a13f66d2e038ef13fd6cbd911d6129a80060110`: **SUCCESS — 3/3 jobs** (`windows-build`, `linux-tests`, `scheduler-rollback-drill`). Es la primera suite general completada después del cambio de laboratorio integrado. La prueba dirigida [#41518980808](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41518980808) también **SUCCESS**.

La tarea fallida de laboratorio era `cmd.exe /C exit 83`, NO el motor candidato firmado. El motor recuperado fue Full CI, NO el 0.28.6 instalado en PC real.

## Tablero con pesos de aceptación productiva (sin inflar)
Centro 12/12; DNS en Windows 10/10; catálogo 8/10; candidato firmado 10/10; permiso editorial/identidad 8/10; respaldo NTFS 10/12; restauración XML de tarea SYSTEM 7/12; conmutación productiva 0/12; recuperación productiva tras corte/reinicio 0/7; publicación/migración 0/5. **Suma: 65/100.**

**Próxima barrera:** candidato real ejecutable de CI con fallo controlado y recuperación del original, seguidos de prueba de transición autorizada bajo editor auténtico. No habilitar `releases/motor-stable.json` ni tocar la instalación del usuario.
