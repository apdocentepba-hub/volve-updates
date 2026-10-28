# VOLVÉ 0.16.8 — identidad de motor y respaldo DNS (solo código)

**NO INSTALAR. NO PUBLICAR EN STABLE.** Es un nuevo desarrollo de preflight de solo lectura, NO un instalador único.

## Implementación
- Lector Go del legado `%ProgramData%\\VOLVE-06\\dns-recovery.json` (BOM UTF-8, modo manual/DHCP, índice de interfaz, servidor DNS original). Acepta metadatos existentes, pero rechaza JSON adicional, modo inválido, IP original sospechosa y respaldo incompleto.
- Inventario Windows **solo lectura**: `Get-NetAdapter`, `Get-DnsClientServerAddress`; exige coincidencia de interfaz original con NIC activa, `127.0.0.1` y `::1` únicamente en interfaz protegida, sin DNS externos añadidos ni otros adaptadores locales sin respaldo.
- Identidad del proceso real en puerto 53: `Get-NetUDPEndpoint` + `Get-CimInstance Win32_Process`. Verifica **mismo PID y mismo ejecutable** para 127.0.0.1 y ::1 y que sea la ruta de la versión objetivo. No confunde un motor viejo que responde con una instalación nueva verificada.
- Opción interna `VOLVE.exe --preflight` sobre el mismo lanzador único; sin otro acceso al Inicio. No realiza ninguna mutación del sistema.
- **NO** ejecuta cambio/restauración real de DNS ni controla tareas o servicios. El respaldo no prueba, por sí solo, un rollback efectivo. No se modificó el Windows del usuario.

## Calidad
- `go test ./...` / `go test -race ./...` / `go vet ./...`: OK para proyecto principal.
- Tests del motor recuperado: OK.
- 105 pruebas Go definidas en el proyecto principal y 21 pruebas en el motor recuperado. Algunas exclusivas Windows sólo se compilaron, no se ejecutaron.
- Compilación de lanzador y prueba Win64: OK; **sin Windows VM**.
- ZIP fuente privado: `VOLVE_0168_PREFLIGHT_DNS_IDENTIDAD_FUENTES_NO_INSTALAR.zip`, SHA256 `8a85332289a1d792207ab42379ad4bad0328230bcf39aa6854ee0c4da44ae5c2`.

## Para la instalación única definitiva
Aún falta mecanismo privilegiado probado de cambio/reinicio motor y watchdog, migración y restauración DNS y tareas con ACL confiables, tres listas reales completas, versión completa firmada, actualizador de TODO el producto, Authenticode y ensayo de Windows/reinicio/VPN/fallo de red.

Canal `stable`: sin manifiesto ni paquetes anunciados. Conservamos protección instalada del usuario.
