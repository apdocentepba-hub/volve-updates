# Canal VOLVÉ 0.28.x — actualizaciones verificadas del Centro de protección

**Estado (29/10/2026): prepublicación. No hay paquete 0.28.4 anunciado como estable y no se debe crear un manifiesto de una descarga inexistente.**

## Canales diferentes, no mezclar claves

- El canal heredado `stable/manifest.json` con `public-key.base64.txt` sirve al actualizador histórico 0.14.x.
- Los centros modernos 0.28.0–0.28.4 consultan **`releases/stable.json` y `releases/stable.json.sig`**.
- En 0.28.x el verificador tiene su **propia clave pública fijada en el ejecutable**, distinta de la del canal heredado. La clave privada nunca debe entrar al repositorio.
- La 0.28.3 solo descarga y verifica la actualización; la 0.28.4 agrega un instalador administrativo integrado para **el panel únicamente**, con nueva validación de firma y SHA-256 antes y durante la copia. El motor DNS residente y las tareas de rescate no se reemplazan.

## Procedimiento de primera publicación

1. Validar VOLVÉ 0.28.4 en Windows 10/11: abrir la interfaz, simular UAC cancelado, instalar una actualización firmada en equipo descartable, probar acceso directo y retroceso.
2. Crear el Release oficial con tag `v0.28.4` y asset `VOLVE_0_28_4_CENTRO.exe`, verificando bytes reales.
3. Generar `releases/stable.json` desde el archivo publicado, ejecutando `tools/preparar_release.py --exe ... --version 0.28.4 --out releases/stable.json`. El archivo contiene la URL fija a GitHub Releases, tamaño y SHA-256.
4. Firmar **los bytes exactos** del JSON fuera de línea mediante `go run tools/sign_manifest.go CLAVE_PRIVADA.txt releases/stable.json`.
5. Publicar `releases/stable.json` y `releases/stable.json.sig` juntos. Comprobar desde la 0.28.3 y la 0.28.4 que ambas verifican el canal.
6. En la 0.28.3 la primera actualización se descarga pero requiere abrir el archivo. En la 0.28.4 las próximas se podrán instalar desde el propio panel con un solo consentimiento/UAC, manteniendo motor DNS en ejecución.

## Seguridad

La aplicación nunca eleva un EXE recién descargado: el **ejecutable actual** realiza la operación administrativa, vuelve a verificar Ed25519/tamaño/huella en el archivo preparado, copia la nueva versión a una ruta versionada de ProgramData, rechaza sobrescrituras y actualiza accesos directos. No modifica servidores DNS, firewall, tareas SYSTEM, hosts ni el catálogo.

### Evidencia de pruebas

- `go test ./...`: aprobado.
- `go test -race ./...`: aprobado.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: aprobado.
- Compilación GUI Windows x64: aprobado.
- Prueba HTTP simulada: manifiesto firmado → descarga → validación del archivo preparado; rechazos por falsificación y datos alterados aprobados.
- Ejecución de UAC y actualización de accesos directos en Windows real: **pendiente**.

**No activar canal estable todavía.** Firma del manifiesto Ed25519 no reemplaza Authenticode para reputación de Windows.
