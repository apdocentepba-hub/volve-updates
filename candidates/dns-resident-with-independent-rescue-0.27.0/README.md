# VOLVÉ 0.27.0 — DNS residente con rescate independiente (BETA EXPERIMENTAL)

Fecha: 29 de octubre de 2026 (Argentina). **No publicar en stable.**

## Entregables

- [Ejecutable Windows 64 bits](https://drive.google.com/file/d/15JkCsAYj78sizvFN5pOurtGEyxGrrhTp/view) — `VOLVE_Setup_0270_DNS_CON_RESCATE_BETA.exe`.
- [EXE, BAT de emergencia, código y pruebas](https://drive.google.com/file/d/13IXHAKvO01Bbsg6RT4PpG9erDY3LeP2L/view).
- SHA-256 del EXE: `c80a9c0075f5f3e7980085052fb5cc17a91c500721cf548722640ef3244248da`.

## Qué está implementado

- Panel Win32 a partir de la 0.26.4, con instalación base, prueba de motor y botón de **instalación/activación DNS explícita** mediante UAC y segunda confirmación.
- Reutiliza caché HaGeZi Full (requiere archivo real con al menos 400.000 dominios) y los catálogos auxiliares; carga filtro de subdominios.
- Motor de DNS local `127.0.0.1:53` / `::1:53` UDP y TCP, con reenvío de nombres permitidos a servidores de referencia.
- Tarea de arranque SYSTEM para motor DNS residente, y tarea SYSTEM separada cada minuto que comprueba dominios bloqueados y permitidos en ambas familias; si falla, intenta volver al DNS automático original. Test CI sobre tareas: [aprobado](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40871025308).
- Validación estricta de propiedad de tareas (ruta, argumentos y cuenta SYSTEM), permisos ACL en scripts y respaldo, inventario por GUID; admite que el índice cambie después de reiniciar.
- Journal `pending` / `active` y ventana de gracia para evitar carrera con tarea de recuperación durante instalación; rollback por errores de activación y recuperación del modo DHCP.
- Actualización del motor por huella del contenido del catálogo, no solo por recuento.
- BAT de emergencia independiente incluido también en el ZIP, que restaura DNS automático tras confirmación.

## Validaciones y límites

- `go test ./... -count=1`, `go test -race ./... -count=1`, `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: OK.
- Compilación PE32+ GUI Windows x64 y compilación de pruebas Windows: OK (estas últimas NO ejecutadas).
- ZIP CRC e igualdad del EXE verificados localmente.
- En Windows CI se verificó el Programador de tareas **sin cambiar ningún adaptador**. Las pruebas anteriores de rollback usaron un adaptador simulado.
- **No existe evidencia de que la activación real, la conectividad y la reversión automática hayan pasado una prueba completa en Windows real.** Por eso NO se recomienda activar en una PC principal. Mantener el BAT independiente.
- Solo se permite activación desde DNS automático y una interfaz física activa; se rechazan DNS manuales, varios adaptadores o inventarios ambiguos.
- No se garantiza bloqueo contra VPN, DoH externo, DNS propio, IP directas ni desinstalación por un administrador.
- No tiene firma Authenticode.
