# VOLVÉ 0.16.1 — motor integral experimental (solo fuentes)

**NO INSTALAR EN WINDOWS. NO DISTRIBUIR AUTOMÁTICAMENTE.**

Avance del diseño de **un único instalador + actualizador de producto completo**, sin múltiples accesos de herramientas.

## Código completado

- `updater`: HTTPS, manifiesto firmado Ed25519, tamaños y SHA-256 del archivo remoto, control de versión y canal; corrección: paquete integral descargado se guarda como `.zip`, no como falso `.exe`.
- `fullbundle`: verifica que el ZIP incluya exactamente panel, motor, agente y catálogo; rutas seguras, hashes individuales y tipo Windows PE64.
- `transaction`: directorios `releases/<version>`, cambio atómico del puntero, journal de recuperación y rollback del puntero si falla la prueba de salud. **No reemplaza servicios ni DNS**.
- `bootstrap`: prototipo de lanzador único que resuelve panel, motor o actualizador según la versión activa; solo componentes de una lista cerrada.
- `ApplySignedCanary`: prueba aislada de firma → descarga HTTPS → ZIP integral → activación y rollback.

## Evidencia local

- 33 pruebas Go: aprobadas (`go test ./... -count=1`)
- Detector de carreras: aprobado (`go test -race ./... -count=1`)
- Revisión estática `go vet ./...`: aprobada
- Compilación prototipo launcher Win64 `GOOS=windows GOARCH=amd64 go build`: aprobada; **no probado funcionando en Windows**.
- ZIP de código fuente personal: `VOLVE_0161_FUENTES_MOTOR_INTEGRAL_NO_INSTALAR.zip`, SHA256 `dfad88d0fe1f043bdb6c3e0a3b889f729029e1550f7888f1bb2fa86a63a620fa`. Respaldo privado en Drive.

## Falta antes de instalar

Integración con tareas y servicio DNS reales, respaldo/restauración por interfaz, cambio entre procesos ejecutándose, recuperación segura ante corte eléctrico y bloqueo, actualización del propio agente, prueba en Windows, firma Authenticode y publicación de una versión realmente verificada.

**Canal `stable`: sin paquetes; no modificar.**
