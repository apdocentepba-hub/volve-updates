# VOLVÉ 0.28.3 — Instalador con integración oficial de navegadores (beta)
Fecha 29/10/2026.

## Alcance real
Nuevo EXE único Windows x64, Centro 0.28.1 conservado y botón Herramientas avanzadas > Integrar navegadores. No necesita ZIP de extensión para el usuario final.

La instalación integral  (opción --install-all) ahora ofrece preparar complementos con la misma elevación UAC ya concedida, pero **únicamente después de validar que la extensión está publicada**. La configuración es voluntaria. Chrome y Edge pueden pedir su propia confirmación de habilitación; Firefox también necesita autorizar la extensión firmada. No hay forma legítima de prometer una única confirmación para los tres navegadores. No se fuerza instalación con políticas empresariales ni se alteran certificados HTTPS.

## Seguridad del mecanismo
- Consulta fija a releases/browser-addons.json y su .sig, con firma Ed25519; valida la firma ANTES de parsear JSON; niega IDs que no tengan 32 letras a-p y URLs Firefox fuera de addons.mozilla.org.
- Registro de extensiones de Chrome/Edge únicamente por sus URLs oficiales de actualización de tienda, sin escribir si falta publicación o existen configuraciones incompatibles.
- Firefox abre el enlace oficial en Firefox, sin políticas forzadas.
- Canal todavía no publicado: muestra un mensaje y **NO modifica el Registro, los navegadores ni el DNS**.
- No suplanta a la extensión piloto de 53 reglas ni proporciona cobertura del catálogo completo. Para funcionar faltan revisión/publicación en Chrome Web Store, Edge Add-ons y Firefox Add-ons.

## Pruebas de código
- go test ./... -count=1 OK
- go test -race ./... -count=1 OK
- GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./... OK
- Compilación Windows GUI PE32+ x64 OK.
- Validación de firma falsa, JSON adicional, IDs inválidos y URL no oficial: tests aprobados.
- **NO probado el flujo GUI ni la instalación de extensiones en Windows real.** No activar canal estable.

SHA256 EXE: 1e053a7e67d3cbfb88d1b1ee0dd404673d008d3c019d8f2e3dc4f41816c0b76b

## Artefactos
- [EXE único en Google Drive](https://drive.google.com/file/d/1EoglFy8MXoxceu2tc5Gyoyl4sG0jUniH/view)
- [Código y tests ZIP solo para desarrollo](https://drive.google.com/file/d/1fSspYDMCKSQkxxavWYSvmhv9ZmO_snhe/view)

## Próxima tarea necesaria
Publicar complementos firmados/validados en tiendas y un catálogo de IDs firmado, comprobar instalación en Windows con Chrome, Edge, Firefox y comprobar redirección HTTPS en cada navegador. Mantener siempre recuperación DNS separada.
