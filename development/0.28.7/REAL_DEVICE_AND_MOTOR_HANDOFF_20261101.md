# VOLVÉ — estado verificable del equipo y próximo bloqueo técnico

**Fecha:** 01/11/2026 (Argentina). **Rama:** `feature/motor-updater-0287-pilot`.
**Propósito:** continuar sin repetir diagnósticos ya acreditados. No es una release ni una autorización de alterar el motor.

## Hechos observados en el equipo del usuario (capturas de esta conversación)

- Actualización del **Centro 0.28.6 a 0.28.7** completada desde el botón «Actualizar VOLVÉ». Ventana **VOLVÉ 0.28.7 — Centro de protección** abierta en Windows real.
- «Verificar seguridad» mostró resultado positivo para motor DNS y consultas de apuestas bloqueadas / dominios seguros permitidos. El diagnóstico indicó DNS local 127.0.0.1 y ::1; servicio al iniciar y rescate aparecían registrados, pero **no se verificó reinicio/recuperación tras corte real**.
- «Actualizar listas» retornó éxito de ejecución y catálogo en caché de **630.446 dominios únicos**, con HaGeZi Full **627.355 entradas**, consulta **2026-11-01 20:03:05 -0300**. Eso demuestra datos observados por el panel, **no** confirmación de que todas las entradas se filtran en DNS ni que cada ejecución descargue cambios.
- PowerShell administrador leyó `Get-ScheduledTask -TaskName VOLVE-CATALOGO-0230 | Get-ScheduledTaskInfo`: `LastRunTime=2026-11-01 19:26:01`, `NextRunTime=2026-11-01 20:26:00`, `LastTaskResult=0`. Esto demuestra tarea horaria programada y última ejecución con código 0, **no** prueba de frescura del catálogo en cada hora.
- Queda **sin resolver la identidad exacta del motor instalado para migración**, su ruta/bytes, tarea SYSTEM precisa y respaldo original protegido. No deducir de la versión del Centro que el motor sea 0.28.7, ni asumir que el usuario tiene la tarea `VOLVE-DNS-SERVER-0270`: auditorías anteriores no siempre la encontraban.

## Pruebas CI / releases ya completadas

- [#41359321257](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41359321257) SUCCESS: Centro real 0.28.6 descargó v0.28.7 desde `main/releases/stable.json` firmado y lo instaló en VM Windows, acceso directo correcto, sin tocar tareas DNS.
- Release pública [v0.28.7](https://github.com/apdocentepba-hub/volve-updates/releases/tag/v0.28.7): EXE de **18.168.832 bytes**, SHA-256 `e451b6289116636986ddd67b39dc15f02e471ebde7be9508b38d7bcb0155b414`; el Centro del usuario coincide visualmente con la versión.
- [#41357474452](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41357474452) SUCCESS: suite piloto Linux, watchdog/Windows y restauración en tareas descartables.
- **Nuevo** [#41360915352](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41360915352) SUCCESS: descargó **exactamente el binario público v0.28.7**, comprobó sus bytes, lo ejecutó bajo SYSTEM en una tarea desechable de Windows con consultas DNS UDP locales, y otro watchdog SYSTEM independiente restauró la tarea original. Adaptadores DNS intactos. **No fue un motor instalado en producción, puerto 53 productivo ni un reinicio real**.

## Bloqueo siguiente para la actualización automática del motor

El Centro 0.28.7 instalado ya descarga/valida paquetes de Centro firmados. El canal separado `releases/motor-stable.json` todavía no está publicado y el botón no conmuta un motor vivo. Para habilitarlo hacen falta:

1. Determinar con evidencia actual la **ruta de instalación** del equipo (migración heredada versus motor ya administrado versus ruta desconocida). Las pruebas del usuario acreditan el DNS activo, **no** por sí solas la tarea exacta; usar inspección privilegiada **solo lectura**, sin solicitar al usuario nuevos pasos hasta que haya un candidato firmado y un plan de instalación viable.
2. Motor de distribución con manifiesto Ed25519 de la **clave editorial auténtica**, paquete verificado con Full catalog, versión y compatibilidad; publicar únicamente con controles finales.
3. Driver productivo de conmutación/rollback con mutex kernel compartido, autorización editorial para el **hash exacto del motor antiguo**, respaldo sellado de EXE/XML, watchdog SYSTEM instalado, revalidaciones y prueba tras reinicio de **la misma VM persistente**. Las rutas actuales del watchdog siguen explícitamente limitadas a tareas CI; no eliminar esas barreras para apresurar un release.
4. Verificar DNS IPv4/IPv6, bloques y dominios permitidos, Internet, catálogo, reinicio, fallo forzado y restauración antes de abrir actualización del motor en el Centro.

## Restricciones inamovibles

- No cambiar el DNS, las tareas SYSTEM, el motor, el catálogo ni los mecanismos existentes en el equipo del usuario sin ensayo y aprobación. No pedirle reinstalar la 0.28.6/0.28.7 ni repetir las pruebas ya realizadas.
- Mantener VOLVÉ **gratuito**, privacidad por diseño, sin telemetría identificable.
- No usar una firma CI efímera como identidad editorial de producción, ni publicar `motor-stable.json` antes de contar con driver/reversión reales.
- Las 5/10 puertas del plan histórico no representan tiempo restante; actualizar solo cuando se cumplan criterios de aceptación.

**Próxima intervención técnica:** construir una ruta de recuperación productiva verificable y ensayarla en Windows persistente; resolver la bifurcación real del motor instalado antes de ofrecer instalación en PC.
