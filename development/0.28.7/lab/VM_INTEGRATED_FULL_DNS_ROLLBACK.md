# VOLVÉ 0.28.7 — recuperación real de motor DNS de laboratorio en VM persistente

**NO ES UN INSTALADOR. NO PUBLICAR. NUNCA ejecutar en Windows anfitrión con VOLVÉ 0.28.6.** Este procedimiento comprueba que un watchdog SYSTEM devuelve la tarea a un motor **completo** de laboratorio después de sustituirla por una acción fallida y reiniciar Windows. El candidato que falla es el **simulador `cmd.exe /C exit 83`**, NO un ejecutable nuevo firmado. El motor original también es una compilación de CI, NO el ejecutable 0.28.6 del usuario. No supone autorización editorial ni actualización productiva.

## Preparación previa

- En Hyper-V, comprobar que `VOLVE-LAB-0287` tiene un **punto de control funcional** llamado `ANTES-INTEGRACION-MOTOR-DNS-0287`. Crear uno nuevo antes de intervenir si falta.
- No mantener tareas anteriores `VOLVE-CI-FreshMotor-*` o `VOLVE-CI-BootRecovery-*` en ejecución. Las pruebas anteriores con IDs `202611020001` y `20261102000201` ya fueron limpiadas en la VM del usuario.
- Descargar el artefacto del workflow `volve-0287-vm-integrated-full-dns-rollback.yml` sólo cuando GitHub Actions haya terminado con `SUCCESS`. Extraer **todos** los archivos en `C:\Lab\Integrated` dentro de la VM. Comprobar el manifiesto SHA-256 incluido.
- Utilizar exclusivamente un **LabId nuevo** `20261128000101`. No reutilizar carpetas de ensayos anteriores.
- Abrir Windows PowerShell **como administrador en la VM**. Habilitar historial del Programador de tareas antes de preparar.

## Pasos

```powershell
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\Integrated\vm_full_motor_reboot_dns.ps1" -Mode Probe
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\Integrated\vm_integrated_real_dns_rollback.ps1" -Mode Probe

# El motor real de CI se pone en marcha para comprobar 6 DNS y se detiene.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\Integrated\vm_full_motor_reboot_dns.ps1" -Mode Prepare -LabId 20261128000101 -MotorExe "C:\Lab\Integrated\VOLVE_CI_FreshDNS53.exe"

# Respaldo del XML original y watchdog SYSTEM, luego sustituye SOLAMENTE
# la tarea descartable por el candidato cmd.exe que falla al iniciar.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\Integrated\vm_integrated_real_dns_rollback.ps1" -Mode Arm -LabId 20261128000101
```

**DETENERSE** si Arm no muestra `ARMED`. No improvisar un segundo Prepare o Arm en la misma carpeta; preservar evidencias para diagnóstico.

Antes de reiniciar, conservar una muestra del nuevo observador nativo incluido en el kit:

```powershell
$probe = 'C:\Lab\Integrated\VOLVE-CI-BootObserver.exe'
& $probe --observe | Set-Content -Encoding ASCII 'C:\Lab\Integrated\boot-before.json'
if ($LASTEXITCODE -ne 0) { throw 'No hay evidencia nativa del arranque inicial' }
```

El observador sólo consulta WMI, el evento Kernel-General 12 y el tiempo de actividad del kernel. No autoriza ni modifica el DNS. Conservar la muestra original fuera de la VM para auditoría.

Reiniciar **solamente Windows invitado dentro de la VM** desde Inicio → Reiniciar. No reiniciar host ni restaurar checkpoint salvo fallo real del invitado. El watchdog SYSTEM intentará restaurar la tarea original y arrancar el motor Full DNS.

Luego de entrar de nuevo en el invitado, comprobar primero el reinicio con el mismo observador:

```powershell
$probe = 'C:\Lab\Integrated\VOLVE-CI-BootObserver.exe'
$p = Start-Process -FilePath $probe -ArgumentList '--verify-later' `
  -RedirectStandardInput 'C:\Lab\Integrated\boot-before.json' `
  -RedirectStandardOutput 'C:\Lab\Integrated\boot-after.json' `
  -RedirectStandardError 'C:\Lab\Integrated\boot-error.txt' `
  -NoNewWindow -Wait -PassThru
if ($p.ExitCode -ne 0) { throw 'El reinicio real no fue acreditado; conservar boot-error.txt' }
```

Conservar ambos JSON. La prueba de arranque es independiente de la comprobación de recuperación. Luego ejecutar:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\Integrated\vm_integrated_real_dns_rollback.ps1" -Mode Verify -LabId 20261128000101
```

Si aparece `PASS: real Windows VM reboot; independent SYSTEM restored REAL Full DNS motor...`, se genera:

`C:\ProgramData\VOLVE-CI-FreshDNS53-20261128000101\integrated-rollback-proof.json`

Copiar **solo el archivo JSON**, no modificar la carpeta protegida; enviarlo para auditoría. La validación exige watchdog SYSTEM con eventos 118/100/201/102 de la misma instancia, motor original real de CI bajo SYSTEM con cuatro sockets locales UDP/TCP IPv4/IPv6 del mismo proceso, seis respuestas UDP correctas, TCP Internet directo, archivos (incluido el comprobador TCP) con hashes correctos y adaptadores/hosts inalterados. El recibo debe corresponder al arranque actual. **No declara una firma productiva**.

Después de recibir confirmación de la evidencia y sólo entonces, dentro de la VM:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\Integrated\vm_integrated_real_dns_rollback.ps1" -Mode Cleanup -LabId 20261128000101
```

`Cleanup` retira exclusivamente las dos tareas descartables; conserva los archivos de prueba. Si `Verify` falla, **no ejecutar Cleanup ni repetir Prepare** y no restaurar el punto de control antes de preservar el informe.

## Límites de aceptación

Este ensayo cubre recuperación tras reinicio del **motor Full CI anterior** con consultas DNS funcionales. **No** incluye el permiso editorial Ed25519 de producción, un binario candidato 0.28.7 firmado y puesto en servicio, ni una migración de VOLVÉ 0.28.6 efectuada en la PC real. La habilitación de actualizaciones automáticas continúa bloqueada.
