# VOLVÉ 0.28.7 — Evidencia auténtica de reboot Windows VM y DNS dual-stack

**Fecha de ejecución y reporte:** 2026-11-02, laboratorio Hyper-V del usuario `VOLVE-LAB-0287`. **Ensayo:** `202611020001`. **Fuente directa:** JSON V4 del usuario `VOLVE_VM_POSTBOOT_DNS_AUDITOR_V4_20261102_160342.json` (esquema 4, `kind=VOLVE_LAB_VM_REBOOT_DNS_AUDIT_READONLY`). Esta es evidencia de un laboratorio externo; no se ha ejecutado remotamente por CI ni se certifica de forma independiente el hardware del usuario.

## REALIZADO Y COMPROBADO

- Instancia del mismo Windows antes/después del reinicio: `boot_before_utc=2026-11-02T18:28:45.632565Z`, `boot_after_utc=2026-11-02T18:42:40.711095Z`, `genuine_new_boot=true`, `within_30_min=true`.
- Se detectó la tarea de laboratorio al arranque, ejecutándose como `SYSTEM`; la acción coincide exactamente con el ejecutable de ensayo y `LastRunTime` es posterior al nuevo arranque. `task_last_result=267009` (estado de ejecución de tarea `0x41301`, **no error**).
- Un proceso motor, iniciado después del nuevo arranque como `SYSTEM`, es dueño de `127.0.0.1:53` y `[::1]:53` por UDP. Hash del motor y catálogo sin cambios, identidad de tarea/proceso corroborada por la herramienta.
- DNS real local: **6/6** consultas UDP con resultados esperados. IPv4: `stake.com` NXDOMAIN (rcode 3), `betwarrior.bet.ar` NXDOMAIN (rcode 3), `example.org` NOERROR (rcode 0). IPv6: mismas tres respuestas esperadas. `queries_attempted=6`, `all_six_expected=true`.
- Evento real `118` (TaskScheduler record 211, `2026-11-02T18:42:42.5980215Z`), `100` (record 213, `2026-11-02T18:42:42.6022493Z`), `200` (record 214, `2026-11-02T18:42:42.6022507Z`), todos con **la misma instancia GUID** `{9230e17c-5f8e-4ce3-8a46-5174c01023a4}`. El historial está habilitado; consulta `ok`, 605 registros leídos, 401 posteriores al arranque. `scheduler_boot_chain_present=true`.
- La primera verificación manual había fallado por argumento `Events` vacío. La auditoría V4 resolvió la ambigüedad del lector: **existían registros de la secuencia 118/100/200**. No fue una evidencia válida de error del motor.

## LÍMITES Y PENDIENTES

- La auditoría V4 **no comprueba conectividad TCP/IP directa a Internet**. Sólo comprueba respuesta DNS del servidor local y propiedad de los sockets. Evitar inferir conectividad externa de `example.org` NOERROR.
- Este es el **motor CI de laboratorio** con catálogo de 400.005 líneas preparado por `vm_full_motor_reboot_dns.ps1`, no la actualización firmada 0.28.6→0.28.7 instalada en la PC del usuario.
- La V4 reporta explícitamente `new_motor_migration_proven=false` y `release_authorized=false`. **No se ha probado la interrupción de migración y su recuperación automática del ejecutable original/tarea XML**, ni el circuito de publicación/editora. No publicar `releases/motor-stable.json`, ni modificar motor o DNS host.
- **Progreso conservador: 65/100 puntos de aceptación técnica del actualizador**, de acuerdo con `VOLVE_0287_ACCEPTANCE_SCORECARD_2026-11-02.md`. El ensayo de arranque de motor CI real es un subcriterio superado; el bloque de 7 puntos requiere **interrupción + recuperación original + DNS e Internet**, aún inconcluso.
- Siguiente actuación en VM: consulta TCP directa a `1.1.1.1:443` y alternativo `9.9.9.9:443` sin modificar adaptadores. Luego preparar un laboratorio aparte de **rollback tras migración interrumpida** bajo watchdog SYSTEM con evidencias de firma editorial. Antes de ello preservar checkpoint y evidencia, y retirar solo las tareas descartables anteriores una vez verificado todo.

**Resultado:** persistencia del motor DNS completo bajo SYSTEM tras un reinicio real de VM Windows, con correlación fuerte de eventos y bloqueo IPv4/IPv6, **COMPROBADA**. Actualización productiva del motor 0.28.7: **NO APROBADA**.

## Anexo — Dos conexiones TCP externas reales desde la misma VM

El operador ejecutó manualmente **dentro del Windows invitado** de la VM, una vez terminada la auditoría V4:

```powershell
"1.1.1.1","9.9.9.9" | ForEach-Object {
  [pscustomobject]@{
    Destino = $_
    TCP443 = (Test-NetConnection -ComputerName $_ -Port 443 -InformationLevel Quiet)
  }
} | Format-Table -AutoSize
```

Resultado aportado directamente en la conversación:

```text
Destino TCP443
------- ------
1.1.1.1   True
9.9.9.9   True
```

**Criterio:** existen dos conexiones de salida TCP a endpoints IPv4 numéricos en el puerto 443 (`True` ambas). Esta es **evidencia del operador**, no incluye una captura horaria firmada ni demuestra conectividad HTTP/IPv6 externa, ni que el DNS del adaptador use el motor VOLVÉ. Unido a las seis consultas V4, demuestra disponibilidad de DNS local controlado y conectividad IP externa **en el mismo laboratorio**. No aporta prueba de una migración firmada 0.28.6→0.28.7 ni del rollback después de un corte.

**Siguiente paso seguro:** conservar estos resultados y limpiar **únicamente** la tarea de laboratorio `VOLVE-CI-FreshMotor-202611020001` ejecutando `vm_full_motor_reboot_dns.ps1 -Mode Cleanup -LabId 202611020001` dentro de la VM, tal como el código restringe explícitamente; el comando detiene la tarea si está corriendo y la desregistra, preservando evidencia. Crear checkpoint limpio de la VM después de comprobar la limpieza y ANTES de experimentar con migración simulada. No restaurar ni eliminar evidencias originales de manera implícita.

**Puntaje total de aceptación técnica del actualizador: se mantiene 65/100** hasta completar prueba separada de recuperación tras actualización interrumpida, con autorización editorial y recuperador independiente SYSTEM.
