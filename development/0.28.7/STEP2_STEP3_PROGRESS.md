# VOLVÉ 0.28.7 — Porcentajes controlados de los pasos 2 y 3

Fecha de corte inicial: 30/10/2026. Rama de desarrollo: feature/motor-updater-0287-pilot. **No es una certificación de funcionamiento en producción**.

## Cómo se calculan

Las cifras son **estimaciones conservadoras de ingeniería por entregables ponderados**, no una medición del tiempo, ni una cantidad de líneas, ni un porcentaje de protección. Se acumula crédito parcial por código efectivamente integrado y verificable; aprobar CI no reemplaza los ensayos sobre un equipo Windows persistente. Nunca publicar como cerrado un paso que no haya aprobado todos sus criterios obligatorios.

### Paso 2 — Actualización del motor DNS: 40/100 (40%)

| Subentregable | Peso | Puntos reconocidos | Estado |
| --- | ---: | ---: | --- |
| Permiso editorial exacto, autenticidad y pinning | 15 | 8 | Validación criptográfica en CI; falta emisión legítima para el motor instalado |
| Respaldo anterior y journal protegido | 15 | 15 | Código y auditorías NTFS probados |
| Watchdog de recuperación SYSTEM independiente | 25 | 5 | Lab descartable; NO hay watchdog productivo |
| Controlador Windows real que cambia y revierte el motor | 20 | 0 | Bloqueado expresamente |
| Tests adversos, DNS dual-stack, identidad, rollback en CI | 15 | 12 | Baterías CI; faltan escenarios productivos |
| Reinicio real repetible de VM persistente | 10 | 0 | Sin ejecutar |
| **TOTAL** | **100** | **40** | **Paso abierto** |

Los seis criterios A–F de STEP2_EXIT_CRITERIA.md siguen sin aprobarse **como condiciones de cierre completas**, aunque hay subtrabajos de esos criterios realizados.

### Paso 3 — Recuperación automática: 30/100 (30%) — CI de política aprobada

| Subentregable | Peso | Puntos reconocidos | Estado |
| --- | ---: | ---: | --- |
| Journal durable y estado recuperable | 15 | 10 | Probado; terminal create-only |
| Recuperación independiente de prueba | 20 | 10 | Pruebas Windows con tareas descartables |
| Política de recuperación al iniciar, bloqueo de concurrencia, reintentos | 15 | 10 | **CI 3/3 aprobada; integración de mutex Windows y watchdog productivo pendiente** |
| Watchdog SYSTEM persistente con arranque Windows | 25 | 0 | Ausente |
| Restitución productiva y comprobación de motor/DNS/Internet | 15 | 0 | Ausente |
| Pruebas de reinicio real en VM persistente | 10 | 0 | Ausente |
| **TOTAL VERIFICADO** | **100** | **30** | **Paso abierto** |

**Trabajo de esta intervención:** \`resident_boot_recovery.go\` y \`resident_boot_recovery_test.go\` agregan una política repetible y no mutante de recuperación al arranque: exige bloqueo exclusivo, respaldo íntegro, journal pendiente, restaurador inyectado y comprobación de identidad/DNS/Internet antes de cerrar el journal. Los tests incluyen fallo del restaurador, caída de red, reintento tras interrupción, concurrencia, corrupción del journal y no repetición de tareas terminadas. Es exclusivamente lógica reutilizable, **NO** un watchdog SYSTEM instalado. La ejecución [#41107808258](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41107808258) terminó **3/3 success** (Windows, Linux, recuperación aislada). Se acreditan **10 de 15 puntos** del subentregable "política de recuperación": el paso 3 se actualiza al **30%**. Los 5 puntos restantes dependen de integrar un controlador persistente real. La prueba de mutex entre procesos es una nueva subetapa aún pendiente de CI, por lo que no agrega puntos.

Ver [CI actual de la política](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41107808258). La última batería completa verde anterior fue [#41106287730](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41106287730).

## Qué no debe confundirse

- Un simulador de recuperación **no** constituye restauración tras reinicio real.
- Un binario compilado para Windows **no** acredita que se ejecutó con éxito en Windows.
- Un journal "pendiente" **no** es una autorización editorial para conmutar el DNS.
- No declarar 100% hasta verificar con criterios de aceptación, reproducir fallos, reiniciar una misma VM real y documentar reversión.
- No tocar \`main\`, \`stable.json\`, \`motor-stable.json\`, las credenciales, el servidor DNS productivo ni la instalación VOLVÉ 0.28.6 del usuario sin los controles y autorizaciones correspondientes.
