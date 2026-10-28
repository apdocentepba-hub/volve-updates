# VOLVÉ 0.16.7 — instalación en dos fases y reversión del motor

**SOLO DESARROLLO. NO INSTALAR NI PUBLICAR AUTOMÁTICAMENTE EN `stable`.**

## Implementado
Se detectó que la migración de tareas se confirmaba antes de comprobar la salud del nuevo motor DNS; si fallaba luego la comprobación, el journal ya había desaparecido. Esto se corrigió en código usando una transacción en dos fases:

1. `BeginTaskMigration`: inspección de tareas, resguardo de definición XML, journal persistente, aplicación y verificación **sin borrar el respaldo**.
2. `CommitTaskMigration`: segunda verificación y confirmación solo después de que el controlador haya comprobado la salud del motor; falla ante journal ausente/corrupto.
3. `RecoverTaskMigration`: restauración de tareas originales en caso de fallo, cancelación o proceso interrumpido; conserva journal cuando la restauración es incompleta.
4. `InstallTasksAndEngine`: coordinador simulado de `Preflight` (antes de cualquier cambio), `StartNew`, `ProbeNew`, `RestorePrevious` y `ProbePrevious`. Los errores de recuperación se declaran `CRITICAL` en vez de informar éxito.
5. Compatible con la API anterior, pero no usar la versión de una sola fase en el instalador final.

**Importante:** `EngineTransition` sigue siendo **una interfaz sin implementación privilegiada real**. Esta versión no toca DNS ni instala tareas del usuario. No resuelve todavía watchdog, configuración DNS por adaptador, reemplazo completo del agente, firma de código Windows ni VM de pruebas.

## Verificación
- 119 pruebas `Test*` definidas; suites Linux aprobadas.
- `go test ./...`, `go test -race ./...`, `go vet ./...`: OK.
- Win64 compilación del lanzador y compilación de tests nativos: OK. **No ejecutados en Windows real**.
- Fuente privada `VOLVE_0167_DOS_FASES_Y_RECUPERACION_FUENTES_NO_INSTALAR.zip` (104246 bytes), SHA256 `a5a9ed46352afbba405f8572b4f4ce56fa44d0228945f0c4b077428c5dc675b0`.
- Canal `stable`: sin paquete firmado real.

**Próximo bloqueo:** controlador nativo Windows con respaldo DNS, transición real de motor y watchdog, comprobación de salud, rollback y prueba en VM. Luego instalador integral con única interfaz y actualizaciones completas firmadas.
