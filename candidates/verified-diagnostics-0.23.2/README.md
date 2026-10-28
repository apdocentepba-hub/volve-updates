# VOLVÉ 0.23.2 — diagnóstico elevado y reporte de catálogo (28/10/2026)

**Beta Windows x64, sin activar el DNS de red.**

## Evidencia del equipo Windows (capturas 0.23.1)
- Estado active; 160/160 políticas propias verificadas, hosts activo, DoH 2/2 verificadas y dos políticas anteriores respetadas.
- Catálogo en caché: **64.251 dominios**, verificación 2026-10-28T23:41:06Z, advertencias 0.
- En la interfaz NO elevada: `schtasks` devuelve `Acceso denegado` para la tarea heredada `VOLVE-CATALOGO-0210`.
- Tras pulsar Sí la instalación elevada informó que registró el actualizador horario. Esto no demuestra que la actualización haya obtenido la lista Full ni que el motor DNS filtre el tráfico.

## Corrección en 0.23.2
- Consulta de tareas SYSTEM desde GUI sin privilegios indicada como **NO verificable sin elevación**, no como fallo de instalación.
- Elegir **NO** abre diagnóstico `--doctor-admin` mediante UAC, de solo lectura, para verificar la tarea desde contexto administrativo.
- Reporte de catálogo por fuente: exige datos de `hagezi_gambling_full` y 400.000 entradas para reconocer que el catálogo masivo está presente; con 64.251 entradas se informa cobertura parcial aunque las advertencias sean 0.
- Resultado final de instalación indica solo que la tarea fue registrada/comprobada y se solicitó su ejecución; nunca afirma descarga exitosa o bloqueo DNS del catálogo.
- Compatible con instalación activa 0.23.1. No cambia binario del motor ni DNS del adaptador; conserva estado y reparación previa.

## Pruebas locales
- `go test ./... -count=1`: OK.
- `go test -race ./... -count=1`: OK.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: OK.
- Build GUI Windows amd64 PE32+ OK y ZIP verificado íntegro.
- SHA-256 EXE: `aa164bbc8390d0f88365c79f4ac3dfcc3e5c83a5c5476b8bd874792b20f99b9f`.

## Descargas
- [Instalador 0.23.2](https://drive.google.com/file/d/1t9GysVE8l1Via3jAzKN2Q3HQa8DiPnK7/view).
- [Instalador y código](https://drive.google.com/file/d/1Myidx7EH3RqWZ5cU4j_0_ueZOdWBxTNO/view).

Pendiente: prueba real en Windows; recepción y validación de HaGeZi Full; activación DNS de red con reversión; protección de aplicaciones/VPN. No publicar stable.
