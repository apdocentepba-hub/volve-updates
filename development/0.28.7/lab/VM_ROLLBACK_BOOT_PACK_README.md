# VOLVÉ 0.28.7 — ensayo de recuperación SYSTEM tras reinicio real de una VM
**Edición:** 2026-11-02. **Exclusivamente VM descartable Windows con checkpoint previo. NO ejecutar en la PC anfitriona con 0.28.6.**

Este paquete NO instala ni actualiza el motor real. Simula una interrupción en la actualización de una **tarea inocua**, dejando un journal pendiente y una tarea **SYSTEM al inicio** que la restaura desde un respaldo XML comprobado y un binario anterior simulado. El verificador exige un reinicio de Windows genuino y eventos 118, 100, 201, 102 de **la misma instancia** del recuperador, además de journal cerrado correctamente. El helper Go `volve-journal-lab.exe` proviene de reconstrucción del código del piloto; no es un binario productivo firmado.

## Requisitos

1. Terminar el ensayo anterior del motor Full DNS53 y ejecutar su `Cleanup` con resultado `LIMPIEZA OK`.
2. Apagar la VM `VOLVE-LAB-0287` y crear en Hyper-V un punto de control llamado `ANTES-PRUEBA-ROLLBACK-0287`. Volver a encender la VM para la nueva prueba.
3. Descargar **únicamente dentro de la VM** el artifact del workflow `VOLVE-0287-VM-RECOVERY-BOOT-LAB-NO-INSTALL`, extraer completo en `C:\Lab\Rollback`. Conservar el manifiesto de hashes.

**Verificación de integridad antes de ejecutar el kit:** obtené el SHA-256 del ZIP descargado con `Get-FileHash -Algorithm SHA256 -LiteralPath <ruta-al-ZIP>` y compará los 64 dígitos hexadecimales (sin distinguir mayúsculas y minúsculas ni el prefijo `sha256:`) con el digest publicado en los metadatos del artefacto del run de GitHub Actions que lo generó. Si falta el digest o no coincide, no extraigas ni ejecutes el paquete.

Después de extraerlo en `C:\Lab\Rollback`, desde PowerShell verificá que el manifiesto corresponda exactamente a los siete archivos del kit y que no haya archivos adicionales. Si la comprobación falla, detené el ensayo y conservá el ZIP sin ejecutar:

```powershell
$root = 'C:\Lab\Rollback'
$manifest = Get-Content -LiteralPath (Join-Path $root 'SHA256_MANIFEST.json') -Raw | ConvertFrom-Json
if ($manifest.schema -ne 1 -or $manifest.vm_only -ne $true -or $manifest.product_release -ne $false -or @($manifest.files).Count -ne 7) { throw 'Manifiesto inválido; no ejecutar el kit' }
$expected = @('boot_recovery_lab.ps1','reboot_event_chain.ps1','vm_cleanup_state_contract.ps1','vm_environment_baseline.ps1','vm_reboot_proof.ps1','VM_ROLLBACK_BOOT_PACK_README.md','volve-journal-lab.exe','SHA256_MANIFEST.json') | Sort-Object
$expectedFiles = @($expected | Where-Object { $_ -ne 'SHA256_MANIFEST.json' })
$listedFiles = @($manifest.files | ForEach-Object { [string]$_.name } | Sort-Object)
if ($listedFiles.Count -ne $expectedFiles.Count) { throw 'Manifiesto incompleto o duplicado' }
for ($i = 0; $i -lt $expectedFiles.Count; $i++) { if ($listedFiles[$i] -cne $expectedFiles[$i]) { throw 'Manifiesto con archivo inesperado' } }
$actual = @(Get-ChildItem -LiteralPath $root -File | Select-Object -ExpandProperty Name | Sort-Object)
if (($actual -join "`n") -cne ($expected -join "`n")) { throw 'Archivos ausentes o inesperados; no ejecutar el kit' }
foreach ($entry in $manifest.files) {
  if ($entry.name -notin $expected -or $entry.name -eq 'SHA256_MANIFEST.json') { throw 'Entrada de manifiesto inesperada' }
  $path = Join-Path $root $entry.name
  $file = Get-Item -LiteralPath $path -ErrorAction Stop
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
  if ($file.Length -ne [int64]$entry.bytes -or $hash -cne [string]$entry.sha256) { throw ('Integridad incorrecta: '+$entry.name) }
}
Write-Host 'PASS: ocho archivos esperados y siete hashes del kit verificados.'
```

4. Ejecutar en PowerShell **administrador dentro de la VM**:
   ```powershell
   wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\Rollback\vm_reboot_proof.ps1" -Mode Probe
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\Rollback\vm_reboot_proof.ps1" -Mode Prepare -RunId 20261102000201 -LabScript "C:\Lab\Rollback\boot_recovery_lab.ps1" -JournalExe "C:\Lab\Rollback\volve-journal-lab.exe"
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\Rollback\vm_reboot_proof.ps1" -Mode AuditPrepared -RunId 20261102000201
   ```
5. **Solo** si aparecen `PREPARED` y el `PASS` de `AuditPrepared`, reiniciar **el Windows de la VM** manualmente; no reiniciar el anfitrión. `AuditPrepared` es de **solo lectura**: exige que la definición XML completa del watchdog SYSTEM coincida con la guardada antes del reinicio, comprueba los respaldos, el candidato y el journal pendiente. **No prueba un reinicio** y no reemplaza `Verify` después de arrancar. Después:
   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\Rollback\vm_reboot_proof.ps1" -Mode Verify -RunId 20261102000201
   ```
6. En caso de éxito debe existir `C:\ProgramData\VOLVE-VM-RebootLab-20261102000201\vm-proof-evidence.json`; enviar ese archivo para auditoría. Si falla, **no limpiar**; conservar journal y eventos.
7. **Solo después de `Verify` exitoso, de conservar el archivo `vm-proof-evidence.json` y de aprobar el ensayo**, retirar las dos tareas descartables con:
   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Lab\Rollback\vm_reboot_proof.ps1" -Mode Cleanup -RunId 20261102000201
   ```

**Cierre seguro:** `Cleanup` rechaza el intento si no existe evidencia de reinicio auténtico, si el comprobante no coincide con el registro protegido, si la cadena de eventos de arranque no corresponde a la misma instancia o si el journal sigue pendiente. Revalida íntegramente ambas definiciones XML de Task Scheduler **antes de eliminar cualquiera**. Después de validar las dos tareas guarda `vm-cleanup-intent.json` bajo ACL protegida. Si se interrumpe tras retirar el watchdog, puede retomar la eliminación del motor ficticio **únicamente** con el mismo reinicio demostrado, el journal restaurado y el intent íntegro. Al finalizar verifica que ambas tareas desaparecieron y deja `vm-cleanup-evidence.json`. Un intent ausente o inconsistente impide interpretar como segura una eliminación parcial. Ante un fallo, no usar `Cleanup` para forzar el cierre: conservar las evidencias e inspeccionar la VM antes de restaurar el checkpoint. Este control no modifica ni recupera VOLVÉ instalado en una PC real.

**Control de entorno de solo lectura:** en `Prepare` se registra una referencia protegida del SHA-256 de HOSTS, los servidores DNS IPv4/IPv6 por interfaz y la huella del XML completo de **todas las tareas del Programador de tareas, incluidas las subcarpetas**. Cada registro incluye la ruta de su carpeta y el nombre. Se excluyen **solamente las dos tareas descartables de la raíz cuyos nombres coincidan con el RunId de este ensayo**: otras tareas `VOLVE-CI-*` de otros RunId y tareas homónimas en subcarpetas también deben coincidir. El inventario deja constancia del mismo conjunto de tareas antes y después, pero no certifica cambios en sus archivos binarios o sus ACL independientes. `AuditPrepared`, `Verify` y `Cleanup` comparan esas observaciones y rechazan cualquier divergencia. El control **no cambia HOSTS, DNS ni las tareas ajenas**. Cambios legítimos por Windows Update o DHCP obligan a revisar el ensayo antes de declarar éxito.

**Alcance limitado**: restaura una **tarea ficticia y journal** después de reinicio real, no el EXE DNS anterior ni una actualización de 0.28.6 a 0.28.7, y no valida la firma editorial productiva. Es un hito intermedio, no la liberación del actualizador. El punto de control evita arriesgar el sistema principal, pero no debe restaurarse antes de preservar evidencias.
