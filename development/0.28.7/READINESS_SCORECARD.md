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
| 5 | Inventario completo e integrado de archivos instalados, servicios, tareas, DNS, listeners/53 y recuperación | Pendiente; las comprobaciones individuales no completan el conjunto | 0% |
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

## Restricciones de seguridad

- 0.28.7 todavía **NO** está listo para instalar sobre la PC del usuario.
- La firma de CI no es una autorización de publicación del editor.
- Ningún test aislado autoriza desactivar o cambiar la tarea DNS productiva.
- Para el hito 5 deben obtenerse las seis observaciones desde Windows, con
  identidad privilegiada comprobada y evidencia vinculada; no marcar flags a mano.
- El progreso sólo aumenta con aceptación comprobada; la fecha no agrega progreso.
