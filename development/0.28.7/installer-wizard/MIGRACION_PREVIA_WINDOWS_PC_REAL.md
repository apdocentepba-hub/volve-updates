# VOLVÉ 0.28.7 — Limpieza previa / migración controlada de PC existente
**Fecha:** 14/11/2026 · **Estado:** diseño de operación, **sin ejecución** · **NO autoriza borrado**.

## Evidencia de PC real (informes del 13–14/11/2026)
Fuentes: `VOLVE_DIAGNOSTICO_PC_REAL.json`, `VOLVE_VERIFICACION_COMPLEMENTARIA.json`,
`VOLVE_PRUEBA_DNS_Y_TAREAS.json`, `VOLVE_HISTORIAL_RESCATE_SOLO_LECTURA.json`
y `VOLVE_CAUSA_DNS_RESCATE.json`. Son observaciones temporales; verificar
nuevamente bajo lock en el momento de iniciar una transacción, no afirmar
que este estado permanece sin cambios.

- Aplicación registrada: **VOLVÉ — Protección y acompañamiento 0.10.2**.
- Directorios detectados: `ProgramFiles-VOLVE` y `LocalAppData-VOLVE`.
- Proceso escuchando DNS TCP/UDP 53 en localhost: `VOLVE_DNS_Server_0270`
  (PID observado 2940; NO usar este PID para actuar posteriormente).
- Tarea SYSTEM `VOLVE-CATALOGO-0230`: preparada, último resultado 0;
  acción observada `VOLVE_Motor_0210.exe`.
- Tarea SYSTEM `VOLVE-DNS-RESCUE-0270`: preparada, cada **PT1M**,
  último resultado 0; acción observada `powershell.exe -File ...`;
  **NO fue observada modificando DNS**.
- Tarea SYSTEM `VOLVE-DNS-SERVER-0270`: ejecutándose, inicio al
  arranque, resultado 267009 (running), acción observada
  `VOLVE_DNS_Server_0270.exe`.
- Adaptador 6: rutas por defecto IPv4/IPv6, DNS **sin** localhost.
  El registro indica `automatic_or_policy` para ambas familias (eso no
  distingue con certeza DHCP de política administrada).
- El motor resolvió `example.com` directamente mediante 127.0.0.1 y ::1,
  pero **no se comprobó bloqueo de apuestas ni salud de motor tras reinicio**.
- Historial operativo Task Scheduler deshabilitado; no atribuir
  cambios DNS a la tarea de rescate sin nueva evidencia.
- Servicios VOLVÉ registrados: ninguno por nombre en el primer inventario.
  **Desconocidos**: archivos residuales exactos, propietarios y hashes de
  cada copia, ProgramData, claves de registro adicionales y navegadores.

## Política para la migración a un solo VOLVE_Setup.exe

**La interfaz vista previa NO instala nada y no necesita limpieza.**
El futuro instalador productivo debe reconocer "migración controlada",
no intentar instalar encima ni reclamar que el host está limpio.

### Fase A: congelar evidencia sin mutaciones
1. Obtener acuerdo informado del propietario, incluyendo riesgo de
   interrupción de Internet y vía de emergencia independiente del soporte.
2. Adquirir mutex protegido y validar si Windows ya tiene otro instalador
   o mecanismo de recuperación activo. Si ocurre, **abortar**.
3. Inventariar EXACTAMENTE las tareas, rutas, ejecutables, ACL NTFS,
   browser policies, HOSTS, DNS adaptadores/familias, rescatador y puertos.
4. Comprobar que las tareas y archivos observados son de VOLVÉ;
   identificadores por nombre o prefijo **no bastan** para autorizar borrado.
5. Aislar datos privados (GUID de adaptadores, servidores DNS reales,
   XML de tareas) del servidor CI, repositorio y tickets de soporte.

### Fase B: respaldo y comprobación DURABLE antes de tocar nada
1. Backup del estado DNS original, familias IPv4 e IPv6, origen de
   asignación automática/manual/políticas y orden de servidores.
2. Guardar XML original de las tareas SYSTEM, ejecutables conocidos,
   configuraciones del catálogo, HOSTS y políticas de navegadores que
   efectivamente sean propiedad del producto.
3. Guardar journal durable y recibido autenticado, sellado con ACL
   SYSTEM/Administrators en carpeta local con creación exclusiva,
   SHA-256 fijada externamente en un recibo firmado.
4. Watchdog independiente y vía de recuperación de emergencia deben
   poder recuperar estado anterior **sin depender de la conectividad**.
5. Si la copia, firma, ACL, verificación o capacidad real de recuperación
   falla, NO pasar a C. No sustituir una copia antigua ni generar un
   recibo de "instalado" falso.

### Fase C: transición y limpieza selectiva
1. Verificar otra vez propietario real de motor/tareas y snapshot DNS
   bajo el mismo mutex, justo antes de modificar.
2. Preparar versión nueva, sin ejecutar motor ni cambiar DNS.
3. Detener/desregistrar SOLO tareas y binarios confirmados como
   anteriores, **después** de la validación de retorno. Nunca matar
   procesos por PID histórico ni detener listeners ajenos de puerto 53.
4. Conservar la copia original bajo ACL restringida durante el periodo
   de recuperación; eliminar restos de archivos **solo después de
   confirmar la nueva versión**, sin destruir el rollback.
5. Desinstalar el registro antiguo 0.10.2 solo si se confirma su
   identidad y su desinstalador no modifica piezas ya migradas.
   No invocarlo a ciegas.
6. Aplicar nueva configuración de manera atómica y registrar cada
   transición; un fallo intermedio reactiva/restaura el estado anterior.

### Fase D: comprobación y fin
1. Validar DNS IPv4/IPv6, ruta del sistema, respuesta de dominio
   legítimo y dominio de apuestas de prueba autorizado, bloqueo por
   navegadores, catálogo firmado, actualizador y colisiones de puerto 53.
2. Ensayar un reinicio y una recuperación real de prueba (incluida
   caída de motor), sin perder conectividad.
3. Mostrar "protegido" solo con pruebas completas y recientes.
4. Tras completar el período de observación y una recuperación
   validada, marcar archivos y tareas antiguas como limpiables,
   con manifest de propiedad y backup que siga disponible.
5. Registrar únicamente datos mínimos para auditoría; nunca exponer
   DNS originales ni identificadores privados en GitHub o en el chat.

## Bloqueos irrevocables de seguridad
- `VOLVE-DNS-SERVER-0270` activo → **NO borrar el ejecutable**.
- Respaldo DNS/hosts/tareas incompleto → **NO limpiar tareas**.
- Firma/permiso editorial, editor auténtico o propiedad dudosa →
  **NO desinstalar**.
- Red/políticas de navegador sin origen verificable → **NO tocar**.
- Rollback no probado con reinicio → **NO activar instalador final**.
- Falla de conectividad → habilitar recuperación de emergencia, nunca
  mantener un DNS roto solo para "evitar desinstalación".

## Estado actual
Los mecanismos de inventario, respaldo en NTFS, recibo firmado y
simulaciones de rollback ya tienen pruebas de laboratorio. **No existe
todavía una operación real y validada de limpieza/migración de la PC del
usuario. No se ejecutó ningún comando para quitar componentes y
no se autorizó hacerlo.**

La finalidad es incorporar este contrato a un único instalador
`VOLVE_Setup.exe` con actualizaciones firmadas y catalogación completa
sin crear iteraciones paralelas ni copiar código propietario de BetBlocker.
