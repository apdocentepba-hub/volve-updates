# VOLVÉ 0.28.7 — Seguridad de reemplazo del motor (piloto)

**NO INSTALAR.** El canal estable y el motor DNS de la 0.28.6 no se modifican.

El código completo de referencia permanece en `complete-source-parts/` como ZIP reconstruible mediante GitHub Actions, y el archivo `VOLVE_0287_PRECHECK_RESCATE_OVERLAY_NO_INSTALAR.zip` superpone las correcciones recientes. CI verifica el SHA-256 del overlay antes de compilar.

## Avances de esta revisión

- Reversión con **contexto independiente de 90 s** cuando se cancela o supera el tiempo una actualización; no reutiliza la cancelación que provocó el fallo.
- Un nuevo comando experimental `--motor-upgrade-preflight` de **solo lectura**, que verifica que el motor y las tareas SYSTEM pertenezcan a VOLVÉ, que las acciones y los scripts de rescate coincidan exactamente, que el registro original de DNS esté activo y que respondan IPv4 e IPv6.
- Rechazo explícito de binarios vacíos, directorios, scripts modificados, tarea ajena, registro de recuperación no activo y registros con campos inesperados.
- Pruebas unitarias Windows y una prueba de cancelación con doble simulado.

**Importante:** todavía no se creó un controlador real de conmutación del motor ni un recuperador independiente post-reinicio; por lo tanto, el CLI piloto no modifica el DNS ni la programación del equipo. Antes de actualizar el motor real debe probarse recuperación persistente después de cortar un proceso y reiniciar Windows, más pruebas de conectividad.

Referencia de ZIP de desarrollo: [Carpeta Drive](https://drive.google.com/drive/folders/1mV1XzqsDqAKOVuw_FWIwaOaSnWmTwt5y).
