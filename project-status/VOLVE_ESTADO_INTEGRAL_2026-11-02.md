# VOLVÉ — Estado integral de entregables y aceptación
Fecha: 2026-11-02 (Argentina). Fuente técnica: `VOLVE_0287_ACCEPTANCE_SCORECARD_2026-11-02.md` y resultados de GitHub Actions. No contiene información privada del equipo del usuario.

## No confundir porcentajes
- **Actualizador Windows 0.28.7: 65/100 puntos de aceptación técnica** (ver tabla). No son porcentaje de líneas de código, tiempo restante o disponibilidad comercial.
- **Habilitación del nuevo motor para instalarse en la PC: NO APROBADA**. Cualquier porcentaje de disponibilidad sería engañoso; se mantienen cerradas las compuertas de seguridad y publicación.
- **VOLVÉ como proyecto total (Windows + Android + web + instalador, soporte y difusión): SIN PORCENTAJE GLOBAL AUDITADO.** Los componentes no comparten aún una matriz total de pesos, criterios de aceptación y evidencias. No extrapolar el 65% a todos ellos.
- **Motor original ya instalado:** ejecutándose con tarea SYSTEM tras un reinicio auténtico de Windows, integridad SHA-256 sin cambios y 6/6 respuestas DNS correctas (4 bloqueos NXDOMAIN, 2 dominios permitidos NOERROR). Esto valida dominios testigo, no todos los sitios y técnicas de evasión.

## Porcentajes aceptados por criterio del ACTUALIZADOR Windows 0.28.7

| Criterio de aceptación | Puntos | Máximo | Cumplimiento |
| --- | ---: | ---: | ---: |
| Centro 0.28.7 | 12 | 12 | 100% |
| Bloqueo DNS existente en Windows real | 10 | 10 | 100% |
| Catálogo y actualización horaria | 8 | 10 | 80% |
| Candidato de motor firmado | 10 | 10 | 100% |
| Autorización editorial + identidad original | 8 | 10 | 80% |
| Respaldo y recuperación NTFS | 10 | 12 | 83% |
| Restauración de la tarea SYSTEM | 7 | 12 | 58% |
| Conmutación productiva integrada | 0 | 12 | 0% aprobado |
| Reinicio real + rescate de actualización interrumpida | 0 | 7 | 0% aprobado |
| Publicación, migración de equipo y validación final | 0 | 5 | 0% aprobado |
| **Total** | **65** | **100** | **65%** |

*Porcentajes de etapa redondeados; el total es suma de puntos, no promedio simple. Las pruebas privadas exitosas de la política de recuperación no equivalen a integración productiva.*

## Estado por componente de TODO VOLVÉ

| Componente | Estado comprobable | Porcentaje total |
| --- | --- | --- |
| Windows — motor 0.28.6 existente | Reinicio físico, identidad SYSTEM, integridad y DNS IPv4/IPv6 6/6 verificados; falta evaluación completa del sistema de bloqueo contra evasión | Sin porcentaje integral independiente |
| Actualizador y motor candidato 0.28.7 | 65/100 según la matriz anterior; no instalado el nuevo motor en la PC | **65% técnico** |
| Instalador único y desinstalador | Existen herramientas y ensayos anteriores, pero no hay una entrega final con aceptación integral comprobada aquí | Sin porcentaje auditado |
| Android | Planificado/pausado; no hay APK Android terminada y validada | Sin porcentaje auditado |
| Web institucional VOLVÉ y recursos de ayuda | Sitio y difusión trabajados por separado; disponibilidad, accesibilidad y funcionalidad actuales no auditadas en esta matriz | Sin porcentaje auditado |
| Instagram/contenidos preventivos | Flujo editorial independiente; no aporta puntos al motor Windows | Sin porcentaje auditado |
| Donaciones voluntarias | Política del proyecto: VOLVÉ siempre gratuito; colaboración opcional | No es criterio de progreso del motor |
| Paquete para VM persistente | Generado mediante Windows CI, incluye motor FULL de LAB, scripts y manifiesto SHA-256; NO demuestra reboot o rollback después de reinicio | Entregable CI aprobado, sin puntaje productivo |

## Evidencia nueva y próxima frontera

- [GitHub #41461382335](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41461382335): suite general piloto SUCCESS (Linux, Windows watchdog y simulación Scheduler).
- [GitHub #41451816961](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41451816961): 5/5 grupos de restauración firmada Windows SUCCESS en fixture.
- [GitHub #41457954683](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41457954683): integración de recuperación y motor FULL con SYSTEM/DNS/TCP reales, **en un mismo arranque**.
- [GitHub #41474701926](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41474701926): contrato DNS del laboratorio, incluidos dos casos válidos y 13 casos negativos, SUCCESS.
- [GitHub #41475879370](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41475879370): VM preboot y empaquetado CI del kit con motor, scripts, hashes e instrucciones SUCCESS. Artefacto `VOLVE-0287-PERSISTENT-VM-LAB-NO-INSTALL`, disponible por tiempo limitado en Actions. **No es instalador ni actualización productiva**.

Siguiente prueba obligatoria: **VM Windows persistente, descartable y con snapshot**, registrar antes, provocar fallo *controlado en laboratorio* de una transición con respaldo firmado, reiniciar efectivamente la misma VM, verificar la recuperación desde watchdog independiente SYSTEM, verificar tarea, hashes, DNS dual-stack, salida a Internet, registro final y limpieza. No usar el equipo productivo.

El kit CI generado sirve para demostrar el **arranque del motor FULL** tras reinicio, pero por sí solo **NO prueba rollback de una actualización interrumpida**. Para cerrar el criterio de rescate se necesita además el controlador firmado instalado y el fallo de migración simulado en la VM.

No publicar `motor-stable.json`, no sustituir el motor de la PC y no afirmar compatibilidad/seguridad integral hasta cerrar las compuertas pendientes.
