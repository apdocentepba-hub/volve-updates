# VOLVÉ 0.16.3 — recuperación transaccional de tareas

**NO INSTALAR / NO PUBLICAR EN STABLE. Desarrollo experimental sin pruebas Windows reales.**

## Avance
- Migración con preflight de las dos tareas: motor (`VOLVE-06-DNS`) y agente (`VOLVE-Actualizaciones`); rechazo de acciones desconocidas/de terceros.
- Exportación del XML original de Windows para preservar acciones, disparadores, principales y ajustes, y journal persistente previo a modificar las tareas.
- Uso de cmdlets de Windows nativos, con motor al inicio y actualizaciones horarias; verificación de cuenta SYSTEM y acciones estables `C:\Program Files\VOLVE\VOLVE.exe`.
- Rollback tras fallo: restauración de tareas previas en orden inverso, recuperación reintentable tras interrupción. Falla crítica explícita si la reversión no se confirma.
- La rutina heredada `RegisterPlannedTasks`, que no guardaba el estado original, fue deshabilitada.
- 58 funciones de pruebas en código; tests Linux, `go test -race` y `go vet` aprobados; build amd64 Windows y compilación de sus tests aprobados. **La parte exclusiva Windows NO se ejecutó en Windows real.**

Fuente de desarrollo privada (Drive): `VOLVE_0163_TAREAS_TRANSACCIONALES_FUENTES_NO_INSTALAR.zip` SHA256 `12f3b2e3d55dfe7b4338d2d4d3e5a026fc1fe3428c6db2914f4b871889ea18ab`.

## Riesgos pendientes
1. Protección real con ACL y bloqueo concurrente del directorio del journal.
2. Integración de las tareas, vigilante y servicio DNS reales, coordinando reinicios y rollback.
3. Catálogo `catalogo.dat` real no extraído del instalador antiguo.
4. Instalador unificado de Windows y actualización automática de todos los componentes.
5. Firma Windows Authenticode, pruebas de Windows real con adaptadores, DNS, reinicio, fallo de red y rollback.
6. `stable/manifest.json` y `.sig` NO deben anunciar esta versión.

**No ejecutar ni distribuir como instalador.** La protección instalada del usuario permanece sin alteraciones.