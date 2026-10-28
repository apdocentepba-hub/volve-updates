# VOLVÉ 0.23.0 — reparación de instalación parcial y tarea del catálogo (28/10/2026)

**Beta para Windows x64: no es un filtro DNS de red validado.**

## Defectos observados en Windows

- La instalación 0.22.0 informó "políticas y hosts aplicados, pero falló la instalación del motor de catálogo: la tarea existe pero no pertenece a esta instalación".
- Un diagnóstico independiente de DNS en `127.0.0.1:53` informó `i/o timeout`; ese servidor no se activa en las betas actuales, por lo que es un resultado esperado, no una prueba de bloqueo masivo.

## Reparaciones incluidas

- Parser estructural del XML de schtasks con UTF-16LE, UTF-16BE y UTF-8, con o sin BOM. La tarea solo se considera propia si coinciden ejecutable, argumento exacto y principal SYSTEM; tareas con acciones adicionales se rechazan.
- Si la tarea heredada `VOLVE-CATALOGO-0210` es de procedencia incierta, se preserva y se utiliza `VOLVE-CATALOGO-0230` para la nueva tarea de actualización cada hora. Nunca se sobrescribe una tarea ajena con `/F`.
- Reparación idempotente de instalaciones que quedaron en estado `pending`: verifica cada valor del Registro y completa únicamente lo faltante, aplica `hosts` sin duplicar, reintenta tarea de catálogo y DoH, después registra `active`.
- Diagnóstico integrado actualizado con estado de la tarea programada y límite explícito del DNS no activado.
- Restauración administrativa limitada a políticas, hosts y tareas identificadas como propias.

## Pruebas

- `go test ./... -count=1`: OK (Linux).
- `go test -race ./... -count=1`: OK (Linux).
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: OK.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build`: PE32+ AMD64 (GUI), OK.
- ZIP verificado; SHA-256 del EXE R2: `60b5e439fe7630f9d55fd0b48c0de724a9512e4a397c5bedfb12c67e99e019fa`.

## Respaldo

- [Instalador de reparación R2 en Google Drive](https://drive.google.com/file/d/13rW-nAWYcdUfukCgzua8e5p0ey7sTJ0e/view).
- [Código + instalador R2 en Google Drive](https://drive.google.com/file/d/14ZmtYdDrxzljS66-xB0eR-1C80NEiV-l/view).

## Lo pendiente

No se ha ejecutado el nuevo instalador en la máquina del usuario ni se ha activado o comprobado el motor DNS de loopback. El catálogo de HaGeZi Full se descarga pero **no filtra a nivel de red** en esta beta. No afirmar protección integral frente a VPN o aplicaciones con resolutores propios; no publicar en `stable`.
