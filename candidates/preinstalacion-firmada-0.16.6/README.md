# VOLVÉ 0.16.6 — preinstalación firmada y corrección de tarea DNS

**Código fuente de desarrollo. NO instalar ni publicar en stable.**

## Corrección de protección
Encontramos un error **crítico** del script prototipo de tareas Windows: configuraba `ExecutionTimeLimit=15 minutos` también para el motor DNS, de ejecución permanente, por lo que Windows podría cortarlo al cumplirse ese tiempo. En los fuentes 0.16.6 la tarea motor tiene `ExecutionTimeLimit=PT0S` (sin límite), reintentos de arranque automáticos y una comprobación que rechaza límites incorrectos. El actualizador mantiene el límite de 15 minutos. Las pruebas Windows compilaron, pero todavía falta ejecutar el Programador de tareas en Windows real.

## Preinstalación verificada
Nuevo módulo `installseed`: verifica un manifiesto firmado con Ed25519 y clave pública anclada, limita a `full-canary` (no estable), comprueba tamaño y SHA-256 del ZIP y el contenido integral de **6 componentes** (motor, panel, agente y 3 fuentes), extrae a una carpeta nueva y privada, verifica una segunda vez todos los hashes; rechaza firmas, claves, archivos, versiones o destinos incorrectos y elimina extracciones incompletas. No cambia el motor, DNS, servicios, registro ni tareas.

## Calidad
- 103 funciones de prueba `Test*` definidas, incluidas algunas solo Windows.
- `go test ./... -count=1`, `go test -race ./... -count=1`, `go vet ./...`: OK en Linux.
- Compilación de pruebas `winsetup` e `installseed` y lanzador `cmd/volve-bootstrap` en Windows/amd64: OK. **No ejecutadas en Windows real**.
- Fuentes respaldadas de forma privada en Drive: `VOLVE_0166_PREINSTALACION_FIRMADA_FUENTES_NO_INSTALAR.zip`, SHA-256 `5b245f9ed27406b0fbb42aab14e35d51d34aeb2ebf52f2973375b3ec78a730c3`. No contiene EXE ni claves privadas.

## Falta para entregar un único instalador
Fuentes de dominio reales revisadas, panel y agente integrales, driver privilegiado Windows con respaldo/restauración DNS, servicios y tareas, reversión real ante fallo, firma Authenticode y ensayos en Windows. No anunciar `stable/manifest.json` / `stable/manifest.sig` con este candidato.

**VOLVÉ actualmente instalado no se modificó.**
