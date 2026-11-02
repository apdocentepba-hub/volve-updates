# VOLVÉ 0.28.7 — auditoría de recuperación integrada (2026-11-02)

**Ensayo:** 20261102000301, Windows VM DESKTOP-IRKD7VH. Comprobante recibido: integrated-rollback-proof.json.

**Comprobado en JSON recibido:** reinicio 2026-11-02 20:03:40 UTC → 21:12:21 UTC; verificación 21:14:52 UTC. Tarea watchdog SYSTEM VOLVE-CI-BootRecovery-20261102000301, eventos 118/100/201/102 con record IDs 2097/2100/2218/2219, mismo GUID ada9a9ba-4185-4f81-9a63-3e7a32483bd5, resultado de tarea 0. Motor recuperado PID 9404, DNS IPv4/IPv6 6 de 6 y TCP 1.1.1.1:443 accesible.

**Integridad declarada:** el comprobante incluye SHA-256 del motor, catálogo, XML de tarea y recibo. No se recibieron sus bytes para recalcular las huellas.

**Resultado:** ensayo integrado post-reinicio aprobado de acuerdo con el verificador y comprobante, recuperando el motor DNS Full CI original bajo SYSTEM. El candidato fallido se simuló con cmd.exe; NO prueba una migración productiva firmada desde 0.28.6 ni la reversión de un candidato 0.28.7 real.

**Pendiente operativo:** cleanup de las dos tareas temporales tras conservar el JSON; esperar confirmación CLEAN de la VM. Sin modificar la computadora principal ni publicar canal motor. Aceptación técnica productiva: 65/100.
