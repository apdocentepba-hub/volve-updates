# VOLVÉ 0.28.1 — corrección visual y experiencia de ayuda

29 de octubre de 2026 · Beta de panel · Windows 64 bits.

Problemas observados en 0.28.0:
- El botón «Necesito un momento» abría el archivo HTML en VS Code porque Windows tenía asociada la extensión con ese editor.
- El botón «Actualizar VOLVÉ» mostraba HTTP 404, porque aún no existe un release firmado publicado.
- La pantalla seguía pareciendo un panel administrativo, con demasiadas acciones de nivel técnico.

Cambios implementados:
- Nueva interfaz nativa Win32/GDI con cabecera verde petróleo, tipografía Segoe UI, tarjetas y botones redondeados, acentos verdes y azules.
- Seis acciones principales; «Probar 100 dominios» se trasladó a Herramientas avanzadas.
- La ayuda abre el archivo local con Edge, Chrome o Firefox por su ruta ejecutable conocida en lugar de la asociación .html del sistema.
- HTTP 404 en manifiesto/sig se interpreta como canal no publicado: mensaje amable; sin bajar ni ejecutar archivos sin firma.
- Sin cambios de DNS, firewall, políticas, motor residente 0.27.0 ni tareas SYSTEM por abrir el panel.

Pruebas: go test ./... OK; go test -race ./... OK; go vet Windows amd64 OK; compilación PE32+ x64 GUI OK; compilación cruzada de binario de tests Windows OK (no ejecutados). ZIP íntegro comprobado.

SHA-256 EXE: 06c6ee98ccd04e17c332b7a3a2c4b012fbb3360fa5e16e71840e129764cadabd

Descargas:
- https://drive.google.com/file/d/1NXxtd387Y9EmZHVlrV1gGifS8xE-9d_B/view
- https://drive.google.com/file/d/10O12razKwsY_wVBdF-7-XTl734RLVZyK/view

Limitaciones: interfaz no probada en la computadora Windows del usuario; no hay release firmado estable ni instalación automática. El rescate real sigue sin validarse ante una caída provocada. No anunciar versión estable.