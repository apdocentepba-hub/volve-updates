# VOLVÉ 0.16.4 — contrato de catálogo del motor real (solo desarrollo)

**NO INSTALAR / NO PUBLICAR EN STABLE.**

## Hallazgo y corrección
Se recuperaron los fuentes de VOLVÉ 0.8.1.2, el motor original `volve06/cmd/volvewin`. Se comprobó en código que arranca con `--serve` y que refresca fuentes **cada hora**. La lista de bloqueo real no es un inexistente `data/catalogo.dat`: son los archivos `%ProgramData%\VOLVE-06\feeds\hagezi_gambling_medium.txt`, `stevenblack_gambling.txt` y `arkynx_gambling.txt`.

Por eso el paquete integral pasó de 4 a **6 archivos**: panel, agente, motor y las 3 listas. `catalogcore` valida cada lista usando el analizador del motor original, con mínimos HaGeZi 10.000, StevenBlack 400 y Arkynx 40; rechaza archivos inválidos, dominios demasiado amplios y manipulaciones aun si recalculan SHA-256. **Esto no acredita procedencia ni cobertura**: sigue siendo indispensable firmar el paquete completo y ensayar en Windows.

El motor recuperado ahora puede leer un snapshot versionado vía `VOLVE_BUNDLED_FEEDS` **solo si falta la caché activa**; el lanzador estable pasa esa ruta al ejecutar `--motor`. No se sobrescribe el contenido activo de ProgramData. El motor y lanzador compilan en Windows64 como prototipos, no como instalador.

## Validación
84 funciones de prueba `Test*` entre los dos proyectos fuente; suites ejecutables Linux y detector de condiciones de carrera aprobados; `go vet ./...` OK; builds Windows64 de motor y lanzador OK; tests exclusivos Windows **solo compilados**.

ZIP privado de fuentes en Drive: `VOLVE_0164_CATALOGO_REAL_Y_MOTOR_FUENTES_NO_INSTALAR.zip` (SHA256: `c0c89c59cf4054f83983af8dbc439b1777b6582f0abd3bee4b35578397b7f6df`). No contiene PE ni claves privadas.

## Bloqueos
No hay las 3 fuentes de datos reales firmadas para una distribución inicial. El motor viejo guardaba caché en ProgramData, de modo que un usuario ya instalado puede tenerlas pero **un número en estado.json no basta**. Falta instalador transaccional Windows, autoractualización del agente, integración con tareas, DNS y watchdog, firma Authenticode y ensayo en Windows real. Nunca publicar `stable/manifest.json` ni `stable/manifest.sig` con este prototipo.
