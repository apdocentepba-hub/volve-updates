# VOLVÉ 0.17.2 — cliente firmado por Internet y motor nuevo (laboratorio)

**NO INSTALAR. NO PUBLICAR STABLE.** 28 de octubre de 2026.

## Avances reales
- `updater.CheckManifest` valida HTTPS, Ed25519 y estructura del manifiesto sin modificar disco.
- Se corrigió el staging de descargas: el paquete firmado no sobreescribe archivos existentes y se rechaza una carpeta de staging que sea un enlace simbólico.
- `cmd/volve-online-check` compila a Windows x64 GUI con una ventana inmediata tras la comprobación remota. Verifica la clave pública Ed25519 fija del proyecto, **no carga nuevas claves de GitHub**. Permite comprobar o descargar a staging, pero nunca instala.
- `cmd/volve-bootstrap` implementa `--agent --run` como descarga por Internet de paquete firmado, identificando la versión actualmente activa de VOLVÉ. Sin tarea registrada todavía, no se ejecuta automáticamente.
- `legacy-motor-source/cmd/volvemotor` compila por separado a Windows x64. Sirve DNS local IPv4+IPv6 y refresca listas cada hora; exige respaldos DNS existentes, no cambia adaptadores, servicios o tareas.
- Panel de diagnóstico nativo que requiere respuesta DNS con dominio bloqueado y dominio seguro antes de reportar protección local.

## Pruebas
- 159 funciones `Test*` en el módulo principal; 25 en el motor legado.
- `go test ./... -count=1` y `go test -race ./... -count=1` ejecutados correctamente en Linux para ambos módulos.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...` correcto en módulo principal.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet` correcto en los paquetes reconstruidos del motor. **El viejo cmd/volvewin no se puede compilar para Windows porque faltan assets embebidos en el respaldo histórico**; no se inventaron archivos sustitutos.
- Ejecutables nuevos compilados en formato PE32+ x64 (compilación cruzada, sin pruebas en Windows).

## Backup privado
- [Código y binarios de laboratorio 0.17.2](https://drive.google.com/file/d/1zJ9WggouyXrSN4wbyAqRoZX1e9TIkBeI/view?usp=drivesdk) (solo acceso de propietario).
- 15.982.769 bytes; SHA-256: `626f5275a3abc7c9a38d6b27f246e702877a47c5b9626436bbe3e8fde566b809`.

## Lo que impide un instalador de producción
1. Falta `VOLVE_Setup.exe` real y firmado, ACL de backups, recuperación DNS/adaptadores, rollback con watchdog y control exclusivo de instalación.
2. Falta validar en una VM Windows el inicio de tareas y comportamiento frente a cortes, VPN, DoH, IPv6 y fallos de red.
3. Falta el catálogo de feeds completo con permisos de redistribución y el paquete `bundle.json` firmado.
4. El canal `stable` sigue sin `manifest.json` ni firma, **a propósito**, para impedir despliegues falsamente verificados.
5. La descarga de actualizaciones **NO** equivale a actualizarlas automáticamente; su aplicación requiere primero el driver validado.

**La instalación existente no fue modificada y no se registraron tareas nuevas en la computadora.**
