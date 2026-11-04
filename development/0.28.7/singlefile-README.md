> **CI siete componentes (04/11/2026):** el workflow ahora reconstruye el archivo fuente histórico fijado por SHA-256, aplica `singlefile-overlay/enforce_public_seven.py` con reemplazos de anclas exactas y adapta el puente de inventario Windows para admitir **siete** piezas. No se empaqueta `VOLVE_Uninstall.exe`. La compilación de laboratorio está firmada con certificado sintético y sigue siendo **NO INSTALAR / NO RELEASE**. El desinstalador exclusivo del propietario permanece fuera de las descargas públicas.

> **BLOQUEO DE DISTRIBUCIÓN (04/11/2026):** este prototipo usa ocho componentes sintéticos, incluido un marcador `VOLVE_Uninstall.exe`. Es una fixture **solo de CI**, incompatible con el contrato público de **siete** componentes en `unifiedbundle`. Está prohibido distribuirlo como instalador de usuarios. El desinstalador real será una herramienta privada y exclusiva del propietario, sin incluirse en el Setup, sitio, releases, actualizaciones ni artefactos descargables. Hay que reconstruir el empaquetador para siete piezas y repetir todas las pruebas de firma y staging antes de release.

# VOLVÉ 0.28.7 — EXE único: circuito firmado de laboratorio

**Estado:** PILOTO · PR #3 DRAFT · NO INSTALAR · NO RELEASE

## Qué está implementado y comprobado

El piloto de `singlefile-src.tar.xz` arma un **único Windows PE** con un paquete ZIP y un manifiesto **Ed25519** de ocho piezas obligatorias (Centro/actualizador, motor DNS, manifiesto y firma del motor, watchdog SYSTEM, desinstalador, políticas de navegadores y catálogo Full). El bootstrapper acepta **solo** `--verify-bundle`; no instala, no registra servicios o tareas y no cambia el DNS.

- Fuentes del empaquetador: SHA-256 `01294e1d5ce51928098d30bd90f04b7979e1764993d4b419c66489b67676e215`.
- Fuentes del verificador Authenticode original: `authenticode-overlay.tar.xz`, SHA-256 `cdb9cb776552ee9a08668aae71e8031c7b3d4fb3b6fadf6e6690abfb20fc36a0`.
- Fuente **vigente y legible** de autenticación Windows: `authenticode-source/authenticode_windows.go`. La CI comprueba los archivos comprimidos pero reemplaza el Go antiguo por esta versión de código versionado.
- `singlefile-overlay/staging.go`: extracción a destino **nuevo** con nombre `VOLVE-CI-`, validación del contenido antes de crear ese destino, verificación Ed25519 posterior, rechazo de archivos inesperados y enlaces simbólicos.
- `singlefile-overlay/cmd/stageci/`: **puerta combinada** de laboratorio. Antes de intentar la extracción valida, en orden: 1) firma Authenticode incrustada, reconocida por Windows; 2) SHA-256 del certificado de editor externo y SHA-256 de EXE exacto; 3) manifiesto Ed25519 de los ocho componentes con clave pública externa; 4) hashes y tamaños de archivos extraídos. En otra plataforma no verifica la firma de Windows y falla cerrado.

## Evidencias

[Windows CI #41710778201](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41710778201): SUCCESS con firma de prueba, rechazo de certificados/pins incorrectos, firma del PE, revisión del ZIP y extracción.

[Windows CI #41712574367](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41712574367): **SUCCESS** en ejecución de la puerta **combinada** con certificado de CI autoemitido y Ed25519 sintético. Cuatro escenarios negativos pasan sin crear el directorio de extracción: certificado ajeno, hash del EXE incorrecto, clave Ed25519 incorrecta y pin de certificado faltante. Confirmaciones del registro: `PASS VOLVE_DUAL_SIGNED_STAGE_LAB release=0.28.7 items=8 NO_INSTALL NO_DNS_CHANGE`.

La única confianza temporal del certificado sintético se incorpora al almacén LocalMachine del **runner descartable hospedado**. No existe un certificado editorial de distribución en este repo; no se publica su clave privada ni artefactos de la CI.

## Límites — los cinco bloqueos reales de un Setup distribuible

1. **Componentes productivos originales y permisos editoriales:** los ocho binarios del ensayo son **sintéticos**. Falta el motor firmado realmente y la autorización vigente del cambio desde 0.28.6. No convertir un fixture en release.
2. **Instalación transaccional:** falta integrar la base privada del instalador 0.18.5 y el conductor de instalación/actualización, las verificaciones de compatibilidad y los ACL NTFS SYSTEM/Administradores, protegidos de cambios de archivo entre verificación y ejecución (TOCTOU).
3. **Estado del host y selección de ruta:** falta usar el inventario independiente de Windows, que decide instalación limpia vs. migración de 0.28.6 con evidencia verificable. Un flag del instalador no debe declarar el equipo como limpio.
4. **Protección persistente y rollback:** falta registrar el watchdog AtStartup con permisos, confirmar DNS IPv4/IPv6/navegación tras reinicio y asegurar recuperación del motor original si alguna transición falla.
5. **Pruebas de aceptación final:** reinstalación, actualización y desinstalación en VM persistente con snapshots; verificar boot real y recuperación bajo fallos. Ningún resultado de CI sintético acredita la operación en la PC real.

**NO MERGE · NO RELEASE · SIN ALTERACIÓN DE DNS, TAREAS NI EQUIPO DEL USUARIO.**
La aceptación formal previa del **actualizador** sigue **65/100**; es un indicador distinto de terminación del instalador único.
