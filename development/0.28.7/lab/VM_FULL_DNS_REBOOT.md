# VOLVÉ 0.28.7 — prueba REAL de arranque con el motor DNS completo

**Uso exclusivo de ingeniería: una VM Windows descartable, persistente, con snapshot previo.**
No ejecutar en la computadora que tiene 0.28.6 instalada. No es un instalador.
No requiere comprar infraestructura ni habilita despliegues automáticos.

## Por qué es un paso distinto

El [CI de recuperación con motor real #41306065399](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41306065399) demostró que el motor completo puede ser recuperado junto con una tarea SYSTEM y responder en IPv4/IPv6 **en la sesión actual**. No reinició el sistema operativo.

La nueva prueba conserva un mismo kit de laboratorio antes/después del reinicio de una VM Windows accesible:
- `vm_full_motor_reboot_dns.ps1`: prepara una tarea SYSTEM descartable, ejecuta el motor completo temporalmente y registra hashes; después del arranque verifica su identidad y seis consultas DNS; permite limpieza de esa tarea, sin tocar adaptadores.
- `live_dns_boot_event_chain.ps1`: correlaciona los eventos de Task Scheduler 118 (disparo al arrancar Windows), 100 (inicio de tarea) y 200 (inicio de la acción) **para la misma instancia**. Rechaza los eventos 201/102 de finalización de esa instancia: en esta prueba el motor debe seguir vivo.
- `reboot_event_chain.ps1`: convierte el historial nativo de Windows a registros con identidad de instancia.
- `vm_dns_reply_contract.ps1`: valida ID, opcode, RD, banderas reservadas, QDCOUNT y bytes de la pregunta DNS; se conserva con SHA-256 en la carpeta NTFS protegida para contrastar antes y después del reinicio.
- `test_vm_dns_reply_contract.ps1`: prueba dos respuestas DNS válidas con RD=1 y 13 alteraciones de paquete, sin conectarse a la red.
- `test_live_dns_boot_event_chain.ps1`: verifica 17 escenarios negativos, sin iniciar Windows ni tareas.
- `ci_fresh_dns53_windows.go` introduce la variante de ejecución **solo compilable con etiqueta `volveci`**: `--ci-boot-dns53`. Está limitada a 30 minutos; la prueba habitual `--ci-fresh-dns53` conserva sus 95 segundos.

## Requisitos

1. Una **VM Windows propia, persistente, descartable**, administrada por el laboratorio, con snapshot de seguridad. No usar el host físico ni el equipo del usuario.
2. Administrador dentro de la VM; permitir historial **Task Scheduler/Operational** antes de preparar el ensayo.
3. El código VOLVÉ reconstruido y verificado con los hashes SHA-256 fijados en los workflows CI; Go y los overlays de la rama del piloto. Compilar el **motor real** (no el servidor DNS mínimo) desde `build/codigo` con:
   `go build -tags volveci -trimpath -o VOLVE_CI_FreshDNS53.exe .`
4. Copiar juntos `vm_full_motor_reboot_dns.ps1`, `live_dns_boot_event_chain.ps1`, `reboot_event_chain.ps1`, `vm_direct_internet_probe.ps1` y `vm_dns_reply_contract.ps1` a la misma carpeta de la VM. El ejecutable es **de laboratorio y sin autorización editorial de producción**.
5. El DNS/53 de loopback debe estar libre y no existir la tarea productiva `VOLVE-DNS-SERVER-0270` dentro de la VM.

## Secuencia en la VM, PowerShell elevado

```powershell
$lab='C:\Lab\vm_full_motor_reboot_dns.ps1'
$id='202611010001'
& $lab -Mode Probe
& $lab -Mode Prepare -LabId $id -MotorExe 'C:\Lab\VOLVE_CI_FreshDNS53.exe'
# Tomar snapshot si todavía no se hizo. Reiniciar manualmente SOLO la VM.
# Tras el arranque, ejecutar dentro de los primeros 30 minutos:
& $lab -Mode Verify -LabId $id
& $lab -Mode Cleanup -LabId $id
```

El kit queda bajo `C:\ProgramData\VOLVE-CI-FreshDNS53-<id>`. La prueba comprueba que el paquete Full de laboratorio tiene 400.005 registros (400.002 sintéticos más los dominios de control). En `Prepare` arranca una tarea real SYSTEM y comprueba respuestas NXDOMAIN para `stake.com` y `betwarrior.bet.ar`, y NOERROR para `example.org`, desde 127.0.0.1:53 y [::1]:53. Luego detiene la tarea para que el próximo inicio sea causado por Windows.

En `Verify`, se exige un **nuevo LastBootUpTime**, instancia de Task Scheduler 118/100/200 después de ese arranque, proceso en ejecución realmente propiedad de SYSTEM, posesión de los puertos UDP/53 por ese PID, hashes invariantes del motor y catálogo, consultas DNS dual-stack y DNS de adaptadores/archivo `hosts` inalterados. Sin cualquiera de esos requisitos, no produce aprobación. La prueba nunca reinicia la VM por su cuenta.

Si `Verify` devuelve **lista de eventos vacía**, no se declara éxito: el laboratorio puede conservar un proceso DNS arrancado correctamente, pero sin evidencia de la instancia de inicio de Windows. Antes de repetir el reinicio, ejecutar `VOLVE_VM_DIAGNOSTICO_POSTBOOT.cmd` solo dentro de la VM para recopilar estado de tarea, proceso SYSTEM, propietarios UDP53 y resumen de eventos (sin alterar el sistema). No ejecutar de nuevo `Prepare` ni `Cleanup` mientras se investigan los eventos. Si pasaron 30 minutos desde el arranque, el protocolo de certificación temporal expira y requerirá una nueva prueba controlada.

Se escribe `boot-dns-after.json` **solo tras una verificación positiva**. `Cleanup` elimina únicamente la tarea `VOLVE-CI-FreshMotor-<id>`; conserva el kit/evidencia para auditoría.

## CI y alcance de lo demostrado

- [Contrato PowerShell Windows](https://github.com/apdocentepba-hub/volve-updates/actions/workflows/volve-0287-real-vm-dns-boot-contract.yml): verifica sintaxis, correlación de eventos y 17 casos negativos, sin reiniciar.
- [Preparación Windows VM](https://github.com/apdocentepba-hub/volve-updates/actions/workflows/volve-0287-vm-full-dns-preboot-e2e.yml): compila el motor, prepara la tarea y el catálogo, prueba DNS real **antes de reiniciar**, exige que el verificador no declare un reboot falso y limpia la tarea. El runner de GitHub no permanece disponible después de un reinicio real.

**No se ha aprobado todavía el hito 8**. Para cerrarlo hace falta una evidencia `boot-dns-after.json` tomada en la misma VM persistente después de un reinicio auténtico, además de integrar el watchdog de recuperación productiva y demostrar rollback al motor anterior en el ciclo completo. Este ensayo aislado tampoco acredita la firma editorial verdadera ni la migración 0.28.6 de la PC personal. El tablero global de aceptación Windows permanece **65/100 (65 %)**; esos puntos no prueban el ensayo persistente de recuperación de la migración.
