# VOLVÉ 0.28.2 — prototipo de página de ayuda al intentar acceder a un sitio bloqueado

**29 de octubre de 2026**. Desarrollo independiente para Chrome y Edge (Chromium), Manifest V3. **No instalado ni publicado.** El programa VOLVÉ 0.28.1 y el motor DNS residente 0.27.0 no fueron modificados.

## Función
Cuando el usuario intenta navegar a un dominio incluido explícitamente en el módulo de navegador, la regla `declarativeNetRequest` de tipo redirect con recurso `main_frame` dirige a `ayuda.html` de la extensión **antes de acceder al servidor de destino**, incluidas URL HTTPS. Esto evita modificar certificados y no depende de sustitución de NXDOMAIN.

El piloto incluye 53 reglas: **52 dominios conocidos de apuestas** y **un dominio ficticio `volve-prueba-bloqueada.test` para ensayar sin entrar en webs de apuestas**. No afirma que estas 52 entradas estén necesariamente entre los 626.812 dominios de la instalación del usuario.

- Reglas sólo para navegación de primer nivel (sin bloquear recursos embebidos fuera de DNS).
- No captura ni transmite URLs; sin almacenamiento, analítica ni conexión externa.
- Mensaje no punitivo, con acciones sencillas y recursos de Argentina.
- Página incluida dentro de la extensión, junto con CSS independiente. Sin inyección HTTPS, HTTP local, certificados propios ni servicio persistente.

## Entrega y pruebas
[Archivo ZIP del prototipo y fuentes](https://drive.google.com/file/d/1fTYw-av7TGGzjZNVi48_-VknbnwiF_hT/view).
SHA-256 ZIP: `10267a2519b19e988b90109bf906499268f1c864224f66b7e1433d0221110eed`.
Se validaron el JSON de `manifest.json` y `rules.json`, identificadores únicos, recurso de ayuda, alcance `main_frame`, permisos y CRC de ZIP. **No fue posible completar la prueba de navegación en Chromium headless de este contenedor** (timeout), ni en Windows del usuario.

## No confundirse con instalación final
No se incorporó al .exe ni se impuso una extensión sin permiso. En Windows doméstico, la instalación automática de extensiones autoalojadas está limitada por las políticas de Chrome; para distribución sencilla es necesario publicar una extensión autorizada en Chrome Web Store / Edge Add-ons o una ruta equivalente aprobada. Consultar [DNR MV3](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest/) y [distribución de Chrome](https://developer.chrome.com/docs/extensions/how-to/distribute).

La extensión no cubre automáticamente las 626 mil entradas: debe diseñarse sincronización con el catálogo local, respetando límites del motor de reglas de navegador y evitando falsos positivos. No reemplaza el filtrado DNS en otras aplicaciones ni evita VPN o DNS propios. Firefox exige otra implementación y distribución.

## Próximos entregables
- Empaquetado firmado y publicación oficial del complemento para navegadores.
- Puente autenticado local para reflejar los cambios del catálogo, incluyendo validación sin comprometer la privacidad del usuario.
- UI de VOLVÉ para mostrar estado real de complementos y activar la integración consentida, con recuperación.
- Pruebas de navegación HTTPS/HTTP y casos permitidos en Windows antes de activar la redirección por defecto.
