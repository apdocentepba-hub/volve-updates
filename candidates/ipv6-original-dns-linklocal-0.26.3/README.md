# VOLVÉ 0.26.3 — corregir validación de DNS IPv6 de enlace local

**28/10/2026 (Argentina)**. Versión beta. El DNS del equipo **NO se modifica** durante el ensayo.

## Fallo observado en Windows

En VOLVÉ 0.26.2, el botón «Ensayar activación / rescate» falló al leer la configuración original de Windows:

```
unsafe original DNS server in family 1
```

La validación anterior prohibía todo DNS IPv6 link-local (fe80::/10), aunque Windows pueda utilizar un servidor de esas características en una interfaz física. Esto es una **causa posible** del rechazo, no se registró la IP original de la máquina.

## Corrección implementada

- Se conserva sin cambios la dirección DNS IPv6 original en el respaldo; ya no se rechaza automáticamente un servidor de enlace local.
- Se acepta un `fe80::/10` sin ámbito **solo** si la configuración original es `automatic`, o un `fe80::/10%N` si su ámbito numérico coincide con `InterfaceIndex` identificado.
- Se rechazan ámbitos de otra interfaz, enlace local manual sin ámbito, loopback, unspecified, multicast, duplicados, direcciones inválidas y enlace local IPv4.
- Mensajes de validación mejorados, indicando familia, índice y categoría del fallo sin divulgar direcciones DNS completas.
- El resultado del ensayo advierte si Windows tiene DNS IPv6 de enlace local, para impedir que se confunda el respaldo aceptado con la validación real de recuperación.
- Compatibilidad de estado desde 0.26.2; interfaz 0.26.3 conserva el botón y las comprobaciones previas.

## Pruebas locales

- `go test ./... -count=1`: OK
- `go test -race ./... -count=1`: OK
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: OK
- Compilación Windows amd64 GUI: OK (PE32+)
- Integridad ZIP comprobada y SHA-256 del EXE comprobado: `3202c78669a0557583219133b856a0a950a487b80faf17eef37d98383e4b7a0f`

## Entregables

- [Instalador beta 0.26.3 en Google Drive](https://drive.google.com/file/d/1fzFYZK1ZJUplU8kVBRsAH6W-4xKNJWtf/view)
- [Código fuente y ejecutable ZIP](https://drive.google.com/file/d/1PgW2cikpvJLU6w2VuqbO8ab6G7FIaEmo/view)

## Alcance real

No se ejecutó la nueva compilación en el Windows del usuario. Se ensaya el motor con el catálogo descargado y la reversión **simulada**, sin cambiar el DNS del adaptador. Falta una prueba de recuperación real en entorno Windows desechable, con watchdog independiente y rollback de una modificación efectiva. No activar canal `stable`.
