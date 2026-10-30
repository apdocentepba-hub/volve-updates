# VOLVÉ — control de entrega (30/10/2026)

## Propósito y prioridades

**Objetivo de usuario:** pasar una sola vez de la instalación 0.28.6 a un Centro y motor DNS que se actualicen desde **Actualizar VOLVÉ** (o automáticamente, una vez habilitado), sin descargar instaladores cada vez. Mantener bloqueos, DNS, recuperación ante interrupciones y persistencia de reinicio; evitar compras/suscripciones nuevas y no crear automatizaciones de ChatGPT. Una versión piloto con tests verdes NO equivale a producto entregado.

**Estado verificado:** 0.28.7 está en la rama `feature/motor-updater-0287-pilot`, no en el canal productivo. 0.28.6 ya está publicada como [pre-release](https://github.com/apdocentepba-hub/volve-updates/releases/tag/v0.28.6) y `main/releases/stable.json` apunta a ella. A 30/10/2026 **no existe** `main/releases/motor-stable.json`; no hay paquete motor estable y firmado anunciado.

## Evidencia aprobada en CI

- [GitHub Actions #41049825576](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41049825576): motor DNS con 400.002 dominios de prueba, puerto real 53 y consultas IPv4/IPv6 en Windows efímero, sin cambiar adaptadores.
- [GitHub Actions #41057083973](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41057083973): EXE real del Centro firmado con **clave efímera de laboratorio**, ejecutado bajo tarea SYSTEM aislada y restauración por otro ejecutable SYSTEM.
- [GitHub Actions #41061225944](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41061225944): correlación de eventos de arranque de Windows, rechazo de 12 falsos positivos; **no reinició realmente** la VM.
- [GitHub Actions #41062505590](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41062505590): 3/3 trabajos aprobados, chequeo de migración integrado al botón nativo, diagnóstico de firma/versión/compatibilidad/rescate sin modificar el DNS.

## Qué hace el Centro de desarrollo

1. Revisa los canales firmados de Centro y motor con el botón existente.
2. Si hay paquete DNS firmado compatible, lo descarga y verifica, sin activarlo.
3. **Nuevo:** explica directamente en el botón por qué el paquete no se puede instalar: constancia del motor heredado ausente, firma adulterada, Centro incompatible, falta de privilegios o preflight de DNS y rescate fallido. Ninguna de esas comprobaciones altera una tarea SYSTEM ni una regla.
4. No inventa éxito; informa siempre que el cambio productivo sigue bloqueado.

## Bloqueos reales para cumplir el objetivo

1. **Migración heredada sin fricción:** determinar una forma segura de identificar y respaldar el motor instalado 0.28.6. El código actual exige atestación firmada del motor heredado que **no está publicada**. Evaluar si una migración única con instantánea SHA-256, preflight DNS/conectividad, tareas verificadas, copia versionada y rollback independiente puede evitar exigir firma de la versión antigua, **sin** rebajar la firma obligatoria del motor nuevo ni habilitar un downgrade.
2. **Watchdog productivo:** el binario independiente actual solo acepta nombres `VOLVE-CI-*`; no es todavía un recuperador productivo para `VOLVE-DNS-SERVER-0270`. Implementar un componente productivo con identidad exacta, journal con ACL resistente a modificaciones, rollback del binario/tarea y comprobación DNS/Internet. Mantener el bloqueo duro del cambio hasta aprobarlo.
3. **Reinicio persistente real:** ensayar `Prepare -> reinicio -> Verify` en la **misma** VM Windows persistente, y además probar el motor real servido en el puerto 53 después del arranque. No llamar «reboot probado» a un relanzamiento manual del watchdog.
4. **Distribución firmada:** publicar paquete motor firmado por la **clave de publicación actualmente fijada**, `motor-stable.json` y su firma, solo después de aprobar recuperación. La firma de las pruebas de GitHub es efímera y NO puede reemplazar esa clave. Evitar modificar claves actuales sin autorización.
5. **Actualizador desde la instalación real:** migración 0.28.6 -> siguiente Centro + motor, sin desinstalar, sin romper DNS; probar también falta de Internet, archivos adulterados, cancelación, múltiples versiones y recuperación tras fallo.

## Política de entrega

NO publicar un instalador definitivo, no anunciar motor autopublicado, no borrar/restaurar instalaciones de terceros, no crear tareas ChatGPT, no modificar `main/releases/stable.json` ni añadir `motor-stable.json` hasta cumplir las condiciones anteriores. Continuar sobre la misma rama y priorizar una ruta segura hacia el cambio productivo, no generar versiones parciales por cada prueba.

**Siguiente avance sugerido:** construir un plan de migración local que conserve una huella/backup del motor heredado realmente funcional sin obligar al usuario a reinstalar para obtener una atestación histórica; definir y probar su control transaccional sin habilitar todavía la tarea productiva.
