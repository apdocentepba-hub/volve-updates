# VOLVÉ 0.27.2 — Diagnóstico administrativo de solo lectura

**29 de octubre de 2026 · Windows x64 · beta. NO activar stable.**

## Problema observado
El botón **Comprobar protección REAL** de la versión 0.27.1 rechazó la lectura de `C:\ProgramData\VOLVE-Browser-Filter\VOLVE_DNS_rescue_0270.json` con `Acceso denegado`. No demuestra un fallo del motor: el journal está protegido para administradores y SYSTEM mientras el panel suele ejecutarse sin elevación.

## Corrección integrada
- Al pulsar **«Comprobar protección REAL (admin)»**, si falta elevación, solicita UAC con `ShellExecuteW(runas)` y abre un segundo proceso `--healthcheck-admin`.
- Este proceso crea un **panel exclusivo de diagnóstico**: sólo cuadro de informe y botón Cerrar; no expone activación, instalación, actualización ni restauración.
- `--healthcheck` mantiene lectura exclusiva (no escribe archivos ni cambia DNS, Registro, hosts o tareas).
- Si se intenta el diagnóstico sin permisos de administrador, informa **RESPALDO PROTEGIDO / NO VERIFICABLE** sin concluir que el motor esté caído y sin modificar ACL.
- No modifica las tareas `VOLVE-DNS-SERVER-0270` / `VOLVE-DNS-RESCUE-0270` ni reemplaza el ejecutable residente.
- Compatible con instalación 0.27.0 en ejecución; abrir el nuevo EXE es suficiente para diagnosticar y NO requiere reinstalar.

## Verificaciones
- `go test ./... -count=1`: OK.
- `go test -race ./... -count=1`: OK.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: OK.
- Compilación Windows GUI PE32+ x64: OK.
- Compilación cruzada de ejecutable de pruebas Windows: OK; **no ejecutado en una PC Windows real**.
- ZIP verificado (CRC + hash exacto del EXE).
- SHA256: `9ce08db89c3a99d885ff00e3e8ab8b8e5247223eb380f42343b347122c42ce81`.

## Descargas verificadas
- [EXE de diagnóstico 0.27.2](https://drive.google.com/file/d/1jg1igXeSKiBTDUeqgrrH_TXw-TMSFU5L/view)
- [EXE, BAT de rescate, código y pruebas](https://drive.google.com/file/d/1rG2uCrDA2pkDGJizZT_WGYxcr1HzXCpF/view)

## Restricciones
El flujo UAC requiere comprobación manual en el Windows del usuario. La corrección **no** valida recuperación ante corte real del motor, actualizaciones horarias ni resistencia frente a VPN o DNS propio; no representa una prueba adicional de filtrado masivo. No se tocaron los permisos de archivos protegidos; mantener el BAT de recuperación separado.
