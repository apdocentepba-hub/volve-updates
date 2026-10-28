# VOLVÉ 0.16.5 — empaquetado integral (código fuente de desarrollo)

**NO INSTALAR EN WINDOWS. NO PUBLICAR EN EL CANAL STABLE.**

Se incorporó un empaquetador real de releases candidatas `releasebuild` a la base 0.16.4:

- El ZIP requiere **6 componentes exactos**: panel, agente, motor DNS y tres feeds `hagezi_gambling_medium`, `stevenblack_gambling` y `arkynx_gambling`.
- Genera `bundle.json` con nombre, versión, arquitectura, tamaños y SHA-256 individuales. Revalida ZIP antes de entregarlo; falla sin sobrescribir archivos si faltan feeds, hay EXE no PE64, fuentes truncadas o rutas simbólicas.
- Puede consultar por HTTPS las **tres URLs oficiales que usa el motor** desde un entorno de compilación con Internet. Valida tamaño, dominios, y rechaza las muestras de prueba.
- La estación de compilación actual no dispone de red para obtener las tres listas completas. Por eso **no se creó un paquete real ni un instalador** con listas sintéticas.
- Pruebas: **12 nuevas**, 75 funciones Test* del módulo principal; `go test ./...` y `go test -race ./...` OK; `go vet ./...` OK; compilación Win64 del lanzador y de pruebas Windows OK (no ejecutadas en Windows).
- Prueba de error con catálogos ausentes: el builder finalizó con código 1 y **no dejó salida**.

Respaldo ZIP privado en Drive: `VOLVE_0165_EMPAQUETADOR_INTEGRAL_FUENTES_NO_INSTALAR.zip`, SHA256 `c97b3d148c69d93341b6a7aa7db82bb9512143bc0ff0875afc4ecd44e7fd1a46`.

**Pendientes para instalador único usable**: 3 listas reales completas bajo revisión y licencia, integrar instalador con Programador de tareas y DNS, probar recuperación bajo interrupciones en Windows y firmar el canal y ejecutables.

Canal `stable` sigue sin manifiestos ni paquetes anunciados; el equipo Windows del usuario no fue modificado.
