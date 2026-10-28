# VOLVÉ 0.18.7 — integración de activación DNS y bloqueo de actualizaciones

28/10/2026 — **Desarrollo, NO apto para instalar ni publicar como versión stable**.

## Código realmente implementado
- `dnsactivation.GuardScheduledUpdate` impide que el agente horario reemplace componentes si hay un journal de activación o rescate DNS (`pending`, `active`, `recovered`); se detiene también ante registros dañados o permisos insuficientes. Verificación tanto al empezar una comprobación como antes de activar una actualización de componentes.
- `setupinstall.PrepareActivate0180WithStore` prepara una nueva versión, instala el ejecutable de rescate, después verifica el directorio protegido de recuperación y recién entonces permite seguir al controlador DNS. Si no puede preparar el rescate, deja el journal de migración y no modifica adaptadores.
- Integración Windows `activate0180Windows`: conecta migración, controlador DNS nativo, store de recuperación, self-tests y verificación final de tareas. **NO habilitada en el asistente gráfico** porque las operaciones de DNS y la recuperación siguen sin prueba end-to-end en Windows.
- Nuevo paquete auto-verificable para Windows x64 con **cinco** ejecutables.
- Se agregaron pruebas sobre el orden de preparación, detección de corrupción, bloqueo de actualizaciones y conservación de los registros de recuperación.

## Validaciones realizadas
- `go test ./... -count=1` y `go test -race ./... -count=1`: OK, en Linux.
- Motor legado: pruebas Go y `-race` OK, en Linux.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: OK.
- Se compilaron binarios de pruebas Windows de `dnsactivation`, `setupinstall` y `winsetup`. **No fueron ejecutados en Windows**.
- Se compiló el instalador de laboratorio PE32+ AMD64 y se verificaron SHA-256 y tamaños de sus cinco componentes. **No se recomienda ejecutarlo**.

## Respaldo
[Archivo privado de fuentes y ejecutables de laboratorio](https://drive.google.com/file/d/18yjOzn3PGsXuwY6-atL5Wsj44u4d-L7Z/view).
SHA-256: `2ce3f0be1f6d6932519913e68020a49cfe2b59e1e41c93097a8daf98b0144979` (41.272.027 bytes).

## Pendiente para instalador definitivo
- Pruebas nativas Windows de tareas SYSTEM, DNS loopback IPv4/IPv6, conectividad y reversión después de errores o reinicios.
- Habilitar migración y activación mediante el asistente gráfico solamente tras esas pruebas.
- Actualización firmada y reversible del motor DNS activo; publicación de manifiesto stable solo después de ensayos Windows.

**La PC del usuario no fue modificada. La instalación 0.18.0 no debe reemplazarse con este build.**