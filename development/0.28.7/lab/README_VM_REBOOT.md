# VOLVÉ 0.28.7 — ensayo de recuperación tras un reinicio real (MÁQUINA VIRTUAL)

**ESTE LABORATORIO NO ES UN INSTALADOR. NO EJECUTAR EN LA COMPUTADORA PERSONAL.**

## Qué comprueba

El archivo [VOLVE_VM_REBOOT_LAB.ps1](./VOLVE_VM_REBOOT_LAB.ps1) trabaja únicamente con dos tareas temporales, cuyos nombres empiezan con `VOLVE-CI-VM-`. No modifica DNS, navegador, firewall, la instalación estable de VOLVÉ ni la configuración de Windows para navegar. Utiliza `cmd.exe` y `notepad.exe` como ejecutables inofensivos y ficheros binarios simulados.

**Objetivo de la prueba**: preparar un journal y una tarea de recuperación `AtStartup` bajo la cuenta local SYSTEM, cambiar la tarea ficticia y, tras reiniciar de verdad una VM Windows, comprobar que el recuperador restaura la tarea original. La lectura de `Win32_OperatingSystem.LastBootUpTime` debe cambiar después de la preparación; sin esa evidencia la recuperación se rechaza.

## Condiciones obligatorias

- VM Windows 11 desechable, con una instantánea previa; nunca el equipo donde está instalado VOLVÉ 0.28.6.
- Administrador dentro de la VM, PowerShell 5.1, y módulo ScheduledTasks.
- Ejecutable de laboratorio `volve-journal-lab.exe` compilado con `go build -o volve-journal-lab.exe ./cmd/volve-journal-lab` desde el código de VOLVÉ 0.28.7 con los overlays documentados.
- El laboratorio no pide iniciar ni detener motores DNS y no intenta reiniciar Windows automáticamente.
- Ejecutar desde una carpeta estable de la VM. El código verifica que el equipo sea reconocido como virtual y requiere `-ConfirmVirtualMachine` para preparar y limpiar.

## Secuencia para un operador de pruebas (NO para un usuario de VOLVÉ)

En PowerShell **con elevación**, dentro de la VM y con el helper ya compilado:

```powershell
$lab = 'C:\RutaDePruebas\VOLVE_VM_REBOOT_LAB.ps1'
$helper = 'C:\RutaDePruebas\volve-journal-lab.exe'
$testId = '202610291'

# Primera ejecución: solo comprobar sintaxis y modo sin escrituras.
& $lab -Mode ValidateScript -LabId $testId

# Crear tareas TEMPORALES de ensayo y armar recuperador de inicio.
& $lab -Mode Prepare -LabId $testId -JournalExe $helper -ConfirmVirtualMachine

# Crear un checkpoint de la VM, reiniciarla de verdad desde Windows
# (Inicio > Energía > Reiniciar). No ejecutar esta fase en host real.

# Después de que la VM arranque, comprobar recuperación.
& $lab -Mode Verify -LabId $testId

# Si la verificación fue satisfactoria, quitar únicamente las tareas de ensayo.
& $lab -Mode Cleanup -LabId $testId -ConfirmVirtualMachine
```

El directorio `C:\ProgramData\VOLVE-VM-BOOTLAB-<id>` queda como evidencia hasta que el operador decida desechar la VM.

## Criterios de aprobación

1. Las tareas del ensayo se crearon únicamente en la VM con identidad SYSTEM y nombres autorizados.
2. La tarea watchdog tiene un disparador de inicio de Windows y ejecuta el script de laboratorio local.
3. Después del reinicio real, el valor de `LastBootUpTime` es más reciente que el de la preparación.
4. La tarea ficticia recupera exactamente `cmd.exe /C exit 0`.
5. El journal termina en `restored` y el propio watchdog deja constancia de éxito.
6. Se ejecuta sin tocar las tareas de VOLVÉ en producción, ni DNS IPv4/IPv6, ni servicios del equipo.
7. La limpieza retira solo las tareas temporales del ensayo.

## Qué NO demuestra

- No demuestra un corte físico de energía ni tolerancia a corrupción del sistema de archivos.
- No verifica el motor DNS real, tráfico IPv4/IPv6, conectividad, VPN o bloqueo del catálogo.
- No reemplaza las pruebas de restauración de archivos binarios de producción con ACL de Windows y rollback verificable.
- **Hasta ejecutar el ensayo en una VM que efectivamente reinicie, su resultado queda PENDIENTE.** La compilación y el control de sintaxis en GitHub Actions no sustituyen esa prueba.

## Estado del proyecto

- Versión estable, sin cambios: 0.28.6.
- Rama de desarrollo: `feature/motor-updater-0287-pilot`.
- Nunca ejecutar `VOLVE_VM_REBOOT_LAB.ps1` sobre la PC personal ni publicar este procedimiento como actualización estable.
