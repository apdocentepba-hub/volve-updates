# VOLVÉ 0.16.9 — recuperación supervisada del motor y actualización firmada (solo fuentes)

**CANDIDATO NO INSTALABLE. NO PUBLICAR EN STABLE.**

## Cambio central

En el prototipo anterior, el puntero a la versión previa podía restaurarse **y borrarse el journal** antes de haber comprobado que el motor antiguo efectivamente había vuelto a funcionar. Esto rompe la recuperación ante una interrupción o un segundo fallo.

La versión 0.16.9 implementa:

- `transaction.ApplyExistingGuarded`: conserva `pending.json` hasta verificar el reinicio y el filtrado DNS del motor anterior cuando falla el nuevo.
- `transaction.RecoverGuarded` + `upgrade.RecoverInterrupted`: recuperación reintentable después de interrupciones; puntero anterior primero, restablecer y probar motor después, borrar journal **solo cuando pasa**.
- Marcador `engine_guarded`: la antigua recuperación de **solo archivos** rechaza borrar el journal de una actualización de motor.
- Bloqueo del sistema operativo en archivo persistente: `flock` Unix / `LockFileEx` Windows; después de la muerte del proceso, el bloqueo se libera sin borrar el archivo. **Implementación Windows compilada pero no ejecutada.**
- `upgrade.ApplySignedExisting` conecta HTTPS + firma Ed25519 (clave pública fijada) + validación integral + cambio de versión + recuperación supervisada. Solo admite canal `full-canary`, **nunca `stable`**.

## Pruebas

- 124 pruebas `Test*` definidas en el proyecto principal, 21 en el motor antiguo.
- `go test ./... -count=1`, `go test -race ./... -count=1`, `go vet ./...`, suite heredada: **OK**.
- `GOOS=windows GOARCH=amd64 go vet ./...`: **OK**.
- Compilación Win64 del lanzador y binarios de pruebas `upgrade`, `winsetup`, `transaction`: **OK**, **no ejecutados en Windows**.
- Simulaciones: firma válida/falsa, no actualizar si no hay versión nueva, fallo en DNS nuevo, falla de recuperación antigua y segundo intento, caída abrupta con liberación del bloqueo.
- ZIP de código fuente privado (no contiene ejecutables ni claves privadas): `VOLVE_0169_ACTUALIZACIONES_CON_RECUPERACION_FUENTES_NO_INSTALAR.zip`, SHA256 `5bad4a8f8c4f03f360712764cae080a7b735d297a56524ce9490f7afd04e8039`.

## Bloqueos antes de instalar

No existe aún un controlador de motor con privilegios de Windows y **pruebas reales** para reinicio del DNS, coexistencia con watchdog, restauración de adaptadores y tareas, así como una compilación definitiva con catálogo completo validado, firma Windows Authenticode y pruebas de reinicio/fallo. Esto sigue siendo código fuente: **no hay instalador nuevo ni actualizaciones automáticas habilitadas**.

Canal `stable` debe permanecer vacío hasta las pruebas en Windows.
