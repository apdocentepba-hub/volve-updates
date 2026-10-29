# VOLVÉ 0.28.0 — Primer centro renovado y verificador de actualizaciones

**29 de octubre de 2026**. Beta Windows x64; **no activar canal stable**.

## Entregables
- [Ejecutable](https://drive.google.com/file/d/1YhGs9bR0YOWRkHAWkLvHsI7yhDrHK5VI/view)
- [Código fuente, ejecutable y BAT de recuperación](https://drive.google.com/file/d/1-ldEcNlwF2VEEXEi8ai4pBjuhQpTaf_a/view)
- [Vista previa de página de apoyo](https://drive.google.com/file/d/1b3adaaVLGzU0QZu5LyaNUqqMG1rlV3YB/view)

SHA-256 EXE: `7f3b464aaeea2eca1065e8e19e00a182b4def46167ee9a7b1bc9ec0c64ff1636`.

## Implementado
- Rediseño incremental Win32: panel principal con solo estado, diagnóstico, actualización de listas, actualización de VOLVÉ, prueba 100 dominios y ayuda. Controles técnicos en "Herramientas avanzadas".
- Tipografía Segoe UI, encabezados más claros y fondo neutro; no WebView2 ni telemetría.
- Página de ayuda local de apoyo, con 141 y 0800-444-4000, sin capturar navegación. **No reemplaza la página de error de HTTPS**; eso requiere integración de navegador aprobada.
- Cliente de actualizaciones: consulta únicamente `https://raw.githubusercontent.com/apdocentepba-hub/volve-updates/main/releases/stable.json` + `.sig`, exige firma Ed25519 verificada ANTES de parsear JSON, versión mayor, URL de releases GitHub permitida, hash SHA-256 y tamaño exacto del EXE. Descarga a caché si todo es válido, sin ejecutarlo ni instalarlo automáticamente.
- Clave pública del canal fijada en el EXE; **clave privada NO incluida en código ni ZIP público**. Herramienta de firma offline en fuente para publicar en futuro.
- `--install-panel-only`: instala solo acceso directo del panel versionado, sin tocar DNS residente ni tareas de red.
- Se preserva íntegramente motor DNS de la versión 0.27.0 y toda la lógica 0.27.5.

## Pruebas
- `go test ./...`: OK.
- `go test -race ./...`: OK.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: OK.
- PE32+ Windows x64 GUI construido.
- Tests de firma/tampering, origen prohibido, comparación de versiones y SHA-256 incorrecto pasaron.
- ZIP CRC + bytes del ejecutable comprobados.

## Sin validar / pendiente
- **La GUI no fue ejecutada aún en la PC del usuario** (solo compilación cruzada). No reemplazar un motor residente estable solo por probar UI.
- Aún NO se publicó un release firmado con EXE. "Actualizar VOLVÉ" devolverá mensaje de canal no disponible, sin alterar el equipo. Falta automatizar instalación y rollback de actualizaciones de panel/motor.
- Falta firma Authenticode oficial del PE, diferente de Ed25519 del manifiesto.
- Recuperación DNS frente a caída real o reinicio, bloqueo de VPN y DNS externo aún no demostrados.
- No es posible una garantía absoluta de anti-desinstalación frente a un administrador del equipo.

## Siguientes etapas
1. Ejecutar interfaz en Windows de prueba; corregir controles visuales.
2. Publicar primera versión de programa con firma de manifiesto y, cuando corresponda, Authenticode.
3. Renovación atómica del motor + rollback, con medición de salud posterior.
4. Política de DNS externo mediante firewall/WFP con lista de excepciones y reversión; resolver DoH y VPN por procedimientos separados.
5. Integración de página de ayuda por una extensión gestionada de navegador o capa equivalente compatible con HTTPS, no DNS→HTTP inseguro.
6. Verificar fallos y continuidad después de arranque/apagado en VM Windows.
