# VOLVÉ 0.18.6 — migración DNS con bloqueo de actualizador y reversión condicionada

**28/10/2026 | SOLO DESARROLLO | NO INSTALAR | NO PUBLICAR `stable`.**

## Integraciones realizadas en código privado

1. `Prepare0180Components`: conserva journal transaccional mientras la migración no esté finalizada; la versión anterior y el rescatador permanecen disponibles.
2. El agente horario ahora comprueba `Pending0180Migration` **antes de consultar o instalar actualizaciones**. Suspende el cambio si el registro está presente o corrupto.
3. `PrepareActivate0180` coordina migración, arranque protegido del DNS, comprobaciones del motor y verificación del rescatador; **solo intenta revertir versión tras comprobar la restauración DNS**. Ante estado ambiguo conserva el nuevo motor y los respaldos.
4. `Finalize0180Components` exige verificación local final y cambia el marcador de instalación a `dns-active` **antes** de borrar el journal. El actualizador de componentes inactivos rechaza ese modo para no tocar el motor en servicio.
5. Eliminadas rutas fijas de la versión anterior en la instalación inicial. Pruebas nuevas de fallos, marcadores dañados y secuencia de reversión.

## Validaciones

- 208 funciones `Test*` definidas en proyecto principal, 25 en motor legado. Pasaron las suites ejecutadas en Linux y pruebas `-race`.
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...`: OK.
- PE32+ Windows x64 generado en laboratorio; cinco componentes empaquetados y hashes comprobados.
- Migración con los cuatro binarios originales de 0.18.0 en carpeta temporal Linux: OK.
- Binarios de prueba Windows compilados de forma cruzada; **no se ejecutaron en un Windows real**.

## Respaldo privado

[Fuentes y ejecutables de laboratorio 0.18.6 en Google Drive](https://drive.google.com/file/d/1JznfQSDlxU4ynZ9JN5UwDcop0gT9wlNn/view).

ZIP: 41.155.852 bytes; SHA-256: `b37f18f879f4dd2e6853f0a39042a0ed4b79ed66da27ce6636c790ba9bef98f6`.

**Todavía NO se habilitó la activación DNS en el instalador GUI.** El EXE de laboratorio 0.18.6 instala componentes en máquinas limpias sin protección, y no debe instalarse sobre la 0.18.0 del usuario.

**Pendiente:** validación end-to-end de Task Scheduler, DNS y recuperación de adaptadores en Windows; actualización firmada y reversible del **motor activo**; firma Authenticode, catálogo de protección y verificación anti-evasión. Hasta entonces, `stable` sigue sin release y no se modificó la PC del usuario.