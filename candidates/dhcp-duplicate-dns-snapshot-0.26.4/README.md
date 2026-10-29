# VOLVÉ 0.26.4 — recuperar catálogo DNS con servidores repetidos en captura Windows

**28/10/2026 (hora Argentina)** · beta Windows x64 · no modifica adaptadores durante el ensayo.

## Defecto observado en 0.26.3
La PC del usuario mostró:
```
DNS original familia 1 entrada 2: servidor duplicado
```
El validador de snapshots trataba como fallo cualquier DNS repetido informado por Windows, incluso en modo de asignación automática (DHCP). La captura puede contener entradas equivalentes de IPv6 en diferentes formatos. **No se dispone de las direcciones originales de esa máquina ni se sabe aún qué modo tenía asignado.**

## Corrección implementada
- `Snapshot.Validate` acepta servidores repetidos **solo si RestoreMode=automatic**. Preserva las entradas, orden, representación original y contador de repetidos. No deduplica ni reescribe la configuración ni el respaldo.
- En modo `manual` sigue rechazando duplicados: la restauración exacta con `Set-DnsClientServerAddress` aún no está ensayada.
- `Snapshot.DuplicateServers()` cuenta direcciones repetidas mediante normalización netip sin modificar el backup. El panel añade aviso explícito de duplicados y que el rollback verificado continúa siendo SIMULADO.
- Las restricciones de dirección IP (loopback, multicast, inválidas, familias incompatibles y ámbitos IPv6 ajenos) permanecen activas.
- Se actualizan etiquetas a 0.26.4, compatibilidad con estado 0.26.3 y tests nuevos para respaldo JSON con duplicados, captura PowerShell y rollback simulado.

## Pruebas del código
- `go test ./... -count=1`: aprobado Linux.
- `go test -race ./... -count=1`: aprobado Linux.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: aprobado.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags='-H windowsgui -s -w'`: PE32+ x64 aprobado.
- ZIP íntegro, binario igual al EXE, SHA-256: `a614837a92d47940083784ee1128032c5d55277f12b12f657e26a41d780aa8ca`.

## Entregables verificados
- [EXE 0.26.4](https://drive.google.com/file/d/1zVIJloMwY6KxdAJqc6hgNI2MM9I-n7bn/view)
- [Código Go y EXE ZIP](https://drive.google.com/file/d/152RbjMyEF3rPQPOWO36KbDR5i-QCQniA/view)

## Límites y siguientes pasos
- La corrección no ha sido ejecutada en el Windows del usuario.
- No se ha validado recuperación DNS de un adaptador real, watchdog SYSTEM, corte de red ni reinicio.
- El motor de red no queda residente, no se cambia el DNS del equipo y el catálogo masivo no protege aún toda la computadora.
- No anunciar versión `stable` antes de demostrar reversión real en VM Windows.
