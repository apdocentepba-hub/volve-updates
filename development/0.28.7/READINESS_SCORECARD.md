# VOLVÉ 0.28.7 — Scorecard de actualización SIN reinstalar

Última revisión: 2026-10-31. Rama de laboratorio: `feature/motor-updater-0287-pilot`.

**Progreso de ingeniería del piloto: 40% (4/10 puertas de aceptación aprobadas).**
Escala interna de 10 hitos de peso igual; se acredita 10% solamente cuando las pruebas delimitadas del hito aprobaron. Los hitos pendientes pueden tener código parcial. **No** equivale a 40% de confiabilidad, probabilidad de lanzamiento ni permiso para instalar en producción.

| Puerta | Criterio de aceptación | Estado | Crédito |
| --- | --- | --- | ---: |
| 1 | CI de compilación, pruebas Linux/Windows y rollback del piloto | Aprobado; run 41251480434 | 10% |
| 2 | DNS real IPv4/IPv6 en puerto 53 con catálogo de laboratorio, en VM efímera | Aprobado; run 41049825576 | 10% |
| 3 | Tarea temporal SYSTEM, candidato firmado en laboratorio y watchdog independiente en el mismo arranque | Aprobado; run 41057083973 | 10% |
| 4 | Inventarios Windows de tareas y servicios de solo lectura, clasificación conservadora con regresiones | Aprobado; runs 41251480487 y 41252704303 | 10% |
| 5 | Inventario completo e integrado de archivos instalados, servicios, tareas, DNS, listeners/53 y recuperación | En curso: 5/6 inventarios integrados y aprobados en CI Windows; pendiente únicamente estado de recuperación | 0% |
| 6 | Identidad y permiso de migración del motor heredado realmente instalado, firmados por editor legítimo | Pendiente; NO usar firmas efímeras de CI | 0% |
| 7 | Controlador de conmutación productivo protegido con backups, ACL, journal y watchdog independiente | Pendiente; **prohibido cambiar VOLVE-DNS-SERVER-0270** | 0% |
| 8 | VM Windows persistente: conmutar, reiniciar de verdad, verificar servicio DNS y rollback con evidencia auditable | Pendiente; no confundir simulaciones con reinicios reales | 0% |
| 9 | Publicación oficial firmada y Centro compatible con instalación desde programa existente | Pendiente; sin claves privadas en repositorio | 0% |
| 10 | Ensayo integral de migración 0.28.6 -> nueva versión, salud y recuperación, antes de autorización de despliegue | Pendiente; la PC del usuario permanece intacta | 0% |

## Cambio de esta etapa

Nuevos archivos: `inapp/fresh_service_inventory_windows.go`,
`inapp/fresh_service_inventory_windows_test.go`,
`.github/workflows/volve-0287-fresh-service-inventory-readonly.yml`.

La prueba #41252704303 aprobó en Windows real alojado por GitHub.
Detecta servicios vinculados por nombre, nombre visible o ruta de ejecución;
incluye servicios detenidos y renombrados. Rechaza JSON inválido, incompleto,
duplicado, ajeno o sobredimensionado. Es **solo inspección**: no altera servicios,
tareas, DNS, archivos ni registro.

## Avance adicional comprobado — 31/10/2026

**Puerta 5: 83% de sus subcomprobaciones (5 de 6), 0% de crédito global hasta cerrarla.**
El progreso general continúa en **40% (4 de 10 puertas aprobadas)**.

- **Permiso elevado real:** lectura del token de Windows, sin ejecutar cambios.
- **Task Scheduler y servicios Win32:** inventarios independientes, incluidas tareas o servicios anteriores/detenidos/renombrados y rechazo de evidencia ambigua.
- **DNS IPv4/IPv6:** lectura de todas las familias y adaptadores; detecta loopback 127.0.0.0/8, ::1 y IPv4-mapeadas en IPv6; rechaza registros corruptos, repetidos o con familia incorrecta.
- **Integración:** `inapp/fresh_partial_host_probe_windows.go` combina las tres observaciones y **no marca como inspeccionados** los archivos, listeners/53 ni el estado de recuperación. Es un diagnóstico parcial de solo lectura, no un instalador ni una autorización.

**Evidencia real:** [CI de DNS Windows #41253934948](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41253934948) aprobada; [CI de inventario combinado #41254025714](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41254025714) aprobada. En la VM Windows se consultaron un token administrador, cero tareas VOLVÉ, cero servicios VOLVÉ y seis registros DNS. Los escenarios ficticios prueban detección de motores anteriores, DNS locales, permisos insuficientes y respuestas falsificadas.

**Límite de las pruebas:** se consulta el Windows efímero de GitHub, no el Windows del usuario; sin bloqueo transaccional conjunto ni inspección de el estado de recuperación y sus respaldos, el estado no autoriza instalar o conmutar motores.

### Continuación: inventario de archivos y puerto DNS 53

- **Archivos del motor (4/6):** `fresh_motor_file_inventory_windows.go` comprueba una raíz instalada existente y confiable sin modificarla; identifica el motor heredado `VOLVE_DNS_Server_0270.exe`, archivos versionados y el directorio `installed-engines`. Calcula SHA-256 de ejecutables detectados pero **no** infiere una versión firmada ni autoriza instalar. Se agregaron pruebas de rutas no canónicas, archivos no regulares, nombres de motores vacíos y ausencia de la raíz.
- **Puerto 53 (5/6):** `fresh_port53_inventory_windows.go` consulta las conexiones TCP en escucha y los endpoints UDP, identifica ocupación IPv4/IPv6 y considera conservadoramente una dirección IPv6 comodín como potencialmente dual-stack. La política rechaza tanto ocupación TCP como UDP.
- **Integración:** `fresh_host_port53_integration_windows.go` conserva las cinco observaciones y obliga a que `InspectedRecoveryState=false`. El diagnóstico nunca concede instalación sin evidencia independiente de recuperación.

**Pruebas verificadas:** [archivos #41255196849](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41255196849) y [conjunto 5/6 #41255427504](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41255427504), aprobadas en Windows. En el runner efímero, la prueba nativa encontró UDP/53 IPv4 = 1 y TCP/53 IPv4 = 1, y rechazó que eso pueda pasar como puerto libre.

**Pendiente de la puerta 5:** inspeccionar respaldos y journals de recuperación protegidos; exigir evidencia completa, no solo ausencia aparente de archivos, y repetir las lecturas bajo un bloqueo privilegiado antes de habilitar cualquier cambio real. Sin esa última comprobación, esta puerta queda abierta y el progreso global continúa en **40%**.


## Restricciones de seguridad

- 0.28.7 todavía **NO** está listo para instalar sobre la PC del usuario.
- La firma de CI no es una autorización de publicación del editor.
- Ningún test aislado autoriza desactivar o cambiar la tarea DNS productiva.
- Para el hito 5 deben obtenerse las seis observaciones desde Windows, con
  identidad privilegiada comprobada y evidencia vinculada; no marcar flags a mano.
- El progreso sólo aumenta con aceptación comprobada; la fecha no agrega progreso.
