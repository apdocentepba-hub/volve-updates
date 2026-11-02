# VOLVÉ 0.28.7 — Laboratorio integrado de rollback del motor Full DNS
Fecha: 2026-11-02. Rama: feature/motor-updater-0287-pilot.

## REALIZADO
- Se completaron y limpiaron los dos ensayos separados anteriores en una VM Windows persistente del operador:
  1. Arranque real del motor Full DNS de CI bajo SYSTEM, consultas DNS IPv4/IPv6 6/6, conexiones TCP IPv4 2/2.
  2. Reinicio Windows real de watchdog SYSTEM y restauración de tarea ficticia; comprobante vm-proof-evidence.json con eventos 118/100/201/102, resultado 0, journal NO_ROLLBACK:restored, tarea anterior cmd.exe /C exit 0.
- Implementado desarrollo **VM-only** `development/0.28.7/lab/vm_integrated_real_dns_rollback.ps1`: parte del motor completo de CI preparado y detenido; exporta XML de tarea de motor original, registra SHA-256 y plan protegido, prepara watchdog SYSTEM AtStartup, y cambia temporalmente **solo tarea descartable** al candidato artificial `cmd.exe /C exit 83`.
- Al reiniciar Windows invitado, el watchdog intentará restituir XML exacto y arrancar el motor DNS completo; antes de registrar recibo exige proceso bajo SYSTEM, propiedad de UDP53 dual-stack, seis respuestas DNS y adaptadores/hosts sin cambios. Verificación separada exige cadena de eventos del watchdog 118/100/201/102 de la misma instancia, 6 DNS y TCP externo.
- `development/0.28.7/lab/VM_INTEGRATED_FULL_DNS_ROLLBACK.md` contiene instrucciones reproducibles y límite de seguridad.
- Se corrigió el uso accidental del parámetro automático PowerShell `$args` en una validación de tarea.
- GitHub Actions **#41518980808: SUCCESS**, commit `7a13f66d2e038ef13fd6cbd911d6129a80060110`: compila motor Full CI Go, analiza sintaxis, prueba contrato DNS y correlación de eventos, ejecuta **Prepare + Arm** de motor real y watchdog en runner Windows descartable, rechaza `Verify` sin reinicio, limpia ambas tareas, comprueba que el DNS de adaptadores permaneció intacto y empaqueta artefacto.
- Artefacto `VOLVE-0287-INTEGRATED-VM-REAL-DNS-ROLLBACK-NO-INSTALL` (GitHub artifact 13177750384, 10.37 MB, SHA256 ZIP reportado por GitHub `841691482d0c2ca60672d1a499068468b1e2484e76fb2d756e64f08dbe89834a`, expira 2026-11-09). Incluye motor CI de laboratorio, scripts, procedimientos y manifiesto de hashes.
- Pruebas específicas de mutex y recuperación firmada de laboratorio: [GitHub Actions #41517257655](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41517257655) SUCCESS en 3 fases. Esos éxitos no sustituyen toda la batería CI ni una firma editorial productiva.

## COMPROBADO Y LÍMITES
**APROBADO en CI solamente:** preparación integrada, armado de watchdog y candidato descartable, rechazo de falso reinicio y validación de manifiesto. **NO probado aún:** reboot real de esta prueba integrada y verificación de recuperación del motor Full DNS después del reboot en la VM del operador. La aprobación de compilación NO implica un rollback real del motor en Windows físico.

**El candidato que falla es `cmd.exe /C exit 83`, no un motor 0.28.7 firmado.** El motor recuperado es el Full DNS de CI, no el ejecutable 0.28.6 instalado en el host. No hay permiso editorial de producción, ni conmutación del motor del usuario, ni liberación del canal. El usuario no debe ejecutar este kit en su host ni tocar las tareas productivas.

## SIGUIENTE PASO
1. Confirmar punto de control funcional `ANTES-INTEGRACION-MOTOR-DNS-0287` en `VOLVE-LAB-0287`.
2. Descargar artifact #13177750384 únicamente **dentro de VM**, extraer todos sus archivos en `C:\Lab\Integrated`.
3. Ejecutar `Probe`, `vm_full_motor_reboot_dns.ps1 Prepare -LabId 20261102000301` y `vm_integrated_real_dns_rollback.ps1 -Mode Arm -LabId 20261102000301`; abortar ante cualquier error.
4. Reiniciar **únicamente la VM** de manera manual; ejecutar `Verify` con el mismo LabId y adjuntar `integrated-rollback-proof.json`. Solo tras auditoría efectuar `Cleanup`.
5. Si se aprueba, siguiente pendiente: candidato motor real y permiso editorial productivo de migración desde SHA exacto 0.28.6, integrados con watchdog y pruebas posteriores a reinicio.

**Indicador de aceptación técnica del actualizador de producción: 65/100, sin cambio.**

## Resultado posterior — reinicio integrado REAL reportado por operador

**Fecha:** 2026-11-02. **LabId:** `20261102000301`. El operador ejecutó, dentro de su máquina virtual Hyper-V, `Probe`, `Prepare` y `Arm` con los resultados `PASS`, `PREPARED` y `ARMED`. El motor Full CI generó 400.005 líneas de catálogo. El operador reinició Windows invitado y ejecutó `vm_integrated_real_dns_rollback.ps1 -Mode Verify -LabId 20261102000301`.

**Salida textual aportada directamente por operador:**

```text
PASS: real Windows VM reboot; independent SYSTEM restored REAL Full DNS motor, IPv4+IPv6 6/6 and TCP Internet. Evidence: C:\ProgramData\VOLVE-CI-FreshDNS53-20261102000301\integrated-rollback-proof.json
NOT a production signed 0.28.6 -> 0.28.7 migration.
```

**COMPROBADO EN SALIDA DE LA HERRAMIENTA:** ensayo integrado real después del reinicio aprobado según el verificador Windows en VM; recuperador SYSTEM repuso la tarea del motor Full CI, 6/6 DNS dual-stack, TCP Internet. **PENDIENTE AUDITORÍA DE ARCHIVO:** el JSON `integrated-rollback-proof.json` aún no fue adjuntado, por lo tanto no se examinaron independientemente el GUID, los eventos y los hashes concretos; tampoco se confirmó `Cleanup` de este tercer ensayo. Preservar recibo y plan hasta verificar JSON.

**LÍMITES:** candidato fallido es `cmd.exe /C exit 83`, motor anterior es un compilado CI, no la 0.28.6 del usuario; no se ha probado transición productiva firmada 0.28.6 → 0.28.7 ni recuperación de un motor firmado real. Actualizador productivo permanece bloqueado; aceptación técnica general 65/100, sin cambios.

**SIGUIENTE PASO:** adjuntar JSON, auditar campos y después limpiar únicamente tareas de laboratorio mediante `vm_integrated_real_dns_rollback.ps1 -Mode Cleanup -LabId 20261102000301` en la VM, sin borrar evidencia. Próxima prueba de desarrollo: sustituir `cmd.exe` por un ejecutable de motor candidato CI que falle de forma controlada; exigir autorización firmada sólo en un circuito separado con clave editorial auténtica. No habilitar `motor-stable.json`.
