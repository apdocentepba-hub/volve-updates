# VOLVÉ 0.28.5 — Guardia anti-regresión de actualizaciones del Centro

**Fecha:** 29/10/2026. **Estado:** beta Windows x64. No publicar como release estable.

## Defecto corregido

En 0.28.4 el instalador administrativo comparaba la versión entrante solamente contra la versión del **proceso que lo ejecutaba**. Una ventana antigua aún abierta podía instalar una versión más vieja que la versión más reciente guardada en ProgramData y volver a apuntar los accesos directos hacia atrás.

0.28.5 agrega `releaseupdate.HighestInstalledPanel` y `EnsureNoInstalledDowngrade`. Antes de tocar accesos directos comprueba todos los binarios del Centro con nombre versionado y rechaza retrocesos. Rechaza asimismo los nombres controlados que sean carpetas, enlaces o ejecutables vacíos. Una actualización igual solo se vuelve a vincular si coincide su hash SHA-256 con el manifiesto firmado.

Incluye compatibilidad explícita con el estado de 0.28.4. No reemplaza el motor DNS ni las tareas SYSTEM. Los ejecutables anteriores permanecen sin borrar para permitir recuperación manual.

## Pruebas realizadas

- `go test ./... -count=1`: aprobado (Linux).
- `go test -race ./... -count=1`: aprobado (Linux).
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: aprobado.
- Cross-compilación Windows amd64 PE32+ GUI: aprobada.
- ZIP verificado con CRC y correspondencia binaria.
- **GitHub Actions Windows real**: prueba unitaria del control anti-regresión en runner Windows — [ejecución 40919681519](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40919681519), éxito.

## Descargas respaldadas

- [EXE 0.28.5](https://drive.google.com/file/d/1iJffCDSVBnuJQ1xDbKvby4mdh96e7Xs3/view)
- [EXE, código fuente y BAT de rescate](https://drive.google.com/file/d/1VGgKoD57xtUSCWRSFt_jbXNsNQeT1NOZ/view)

SHA-256 del EXE: `6a11e7d79b4c79e5d422f8746c4925ae93189454e8c3c59e373bb423958135c1`.

## Pendiente para dejar de distribuir EXE manualmente

El canal moderno `releases/stable.json` / `releases/stable.json.sig` todavía **NO está publicado**, por lo que no existe una actualización real que la 0.28.3 pueda recibir. Se requiere publicación con firma Ed25519 fuera de línea (clave privada no se sube ni se incluye), asset oficial GitHub Releases, prueba de actualización con UAC y reversión después de fallo. La 0.28.3 solo puede descargar; la 0.28.4+ incorpora instalación del panel con UAC. No confundir con el canal antiguo `stable/manifest.json` del agente 0.14.x.

No se ha probado el EXE completo en la computadora Windows del usuario; las pruebas Windows de este turno abarcan específicamente el control de versión. **No activar DNS ni reinstalar motor como parte de esta beta.**
