# VOLVÉ 0.28.7 — Actualización desde el programa instalado (candidato, NO release)

**Objetivo pedido:** desde el botón nativo **Actualizar VOLVÉ**, sin desinstalación ni necesidad de buscar manualmente otro instalador.

## Qué hace este piloto

1. El botón invoca `--check-all-updates`, que conserva por compatibilidad el comando original `--check-app-updates`.
2. Consulta en paralelo dos canales independientes firmados con Ed25519: `releases/stable.json` para el Centro y `releases/motor-stable.json` para el motor DNS.
3. El Centro conserva su flujo conocido: descarga comprobada con SHA-256, marcador `VOLVE_STAGE_READY` y consentimiento UAC para que **el ejecutable instalado actual**, no el recién descargado, realice la instalación versionada del Centro.
4. Un motor DNS firmado se descarga al caché por usuario únicamente si el Centro cumple la versión mínima firmada. Se verifican firma del manifiesto, nombre, origen, tamaño y SHA-256; si ya está preparado, se verifican los bytes nuevamente.
5. **No se asume la versión del motor heredado ni se intenta actualizar el motor vivo**. El paquete preparado NO se ejecuta y no se cambian DNS, tareas SYSTEM, respaldos ni firewall. Cuando el canal del motor aún no existe, se informa sin romper la actualización del Centro.
6. La comprobación de ambos canales se ejecuta en paralelo para respetar la espera actual de 120 segundos del botón.

## Integración reproducible

El código fuente Windows de referencia de 0.28.7 se reconstruye a partir de diez partes en `complete-source-parts/` y los overlays de recuperación existentes, todos con sus SHA-256 verificados en CI.

El archivo `apply_overlay.go` copia `inapp_motor_update_windows.go` y las pruebas, y conecta dos puntos precisos del GUI y del CLI del Centro. Si el código base cambia, **rechaza** aplicar un parche que no encuentre exactamente una coincidencia. El mismo overlay se usa en los jobs de Linux y Windows de `volve-motor-0287-pilot.yml`.

El código no se copia a `main`, no altera el manifiesto firmado ni el ZIP estable, y **no es un instalador**. Hasta generar un EXE completo firmado y distribuir una nueva versión de Centro en el canal estable, la 0.28.6 instalada seguirá usando su botón original.

## Contrato de instalación y reversión de motor incorporado en el piloto

El nuevo `motorupdate.ApplyManagedWithRollback` exige que el futuro controlador de Windows:
- valide la identidad, versión y firma del candidato antes de actuar;
- confirme un respaldo duradero antes de instalar o conmutar;
- instale el nuevo ejecutable en una ubicación versionada;
- compruebe **por separado** el DNS local y la conectividad externa;
- registre la versión como confirmada **solo cuando ambas comprobaciones resulten correctas**;
- ante cualquier error posterior al respaldo, intente recuperar y comprobar el motor anterior con un contexto independiente del proceso de actualización.

Incluye pruebas de orden correcto, candidato adulterado, versión heredada no identificada, errores en cada fase y cancelación que no debe cancelar el rollback. Es un **contrato con controladores simulados**, no un controlador real de Windows; por tanto no habilita todavía el botón para reemplazar el motor en una PC.

## Windows Task Scheduler: integración del controlador de laboratorio

Se añadió `managed_windows_task_lab_test.go`, una prueba Windows que ejercita `motorupdate.ApplyManagedWithRollback` contra una tarea **SYSTEM real pero temporal e inocua** (`VOLVE-CI-ManagedMotor-<id>`):

- Guarda y sincroniza a disco el XML original del Programador de tareas con SHA-256.
- Copia el candidato **de prueba** firmado con clave efímera a una ruta versionada y modifica únicamente la acción de esa tarea desechable.
- En el caso nominal confirma la operación solo después de las verificaciones; en una falla simulada de conectividad, restaura la acción original y comprueba la recuperación.
- En ambos casos elimina la tarea de laboratorio sin tocar tareas de producción ni puertos, adaptadores o parámetros DNS.

**GitHub Actions aprobado:** [ejecución 40982068789](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40982068789) (Windows, Linux, recuperación en laboratorio). La primera ejecución de este ensayo identificó un problema real de `FlushFileBuffers` al abrir el respaldo en modo lectura; se corrigió usando un descriptor de escritura antes de repetir y aprobar la prueba.

**Límite:** es una prueba del controlador transaccional con tareas reales de Windows, pero **no ejecuta el motor DNS real, no mide conectividad externa real ni valida recuperación tras un corte eléctrico**. No está habilitado el reemplazo del DNS desde la aplicación instalada.

## Registro del motor realmente instalado (nuevo)

Se incorporó `motorupdate.InspectInstalledEngine` y `RecordVerifiedEngine`. El verificador **nunca identifica la versión por el nombre del archivo**: exige registro administrativo, manifiesto Ed25519 firmado, firma separada y SHA-256 del EXE instalado. Rechaza retrocesos, cambios de huella con versión repetida, inventarios alterados, archivos enlazados y ubicaciones ajenas.

El comprobador del botón `Actualizar VOLVÉ` consulta ese inventario para evitar descargar una versión anterior. Cuando el motor heredado 0.28.6 no tiene aún un registro verificable, **no inventa la versión** ni autoriza sustituir el servicio. La prueba de Windows con tarea SYSTEM desechable ya copia los tres archivos del paquete, confirma el inventario firmado cuando la transacción tiene éxito y comprueba que un rollback no registra la nueva versión.

**CI validado:** [GitHub Actions 40983028270](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40983028270), 3/3 jobs aprobados, pruebas Linux y Windows incluidas. Durante el desarrollo se corrigió un falso rechazo de rutas temporales de Windows que usaban nombres DOS 8.3 (`RUNNER~1`) sin ser enlaces: la comprobación de seguridad ahora examina los componentes reales mediante `Lstat`.

Este avance **no habilita la actualización del DNS real**; se debe conectar el inventario a un controlador administrativo real con respaldo, aislamiento de acceso y recuperación ante interrupción antes de publicar un release del motor.

## Lo que falta para una actualización del motor sin reinstalar

- Registrar y verificar la versión/identidad real del motor que está instalado (no deducir de nombre de archivo).
- Implementar el controlador Windows `motorupdate.SwitchDriver` con respaldos inmutables, tareas SYSTEM verificadas, motor versionado, validación de DNS IPv4/IPv6 y conexión externa.
- Conectar journal + watchdog independiente a este controlador; validar reversión durante fallos y cortes, incluidos rechazos de respaldos alterados.
- Publicar un asset oficial del motor y su manifiesto Ed25519 **sin incluir la clave privada en GitHub**.
- Verificar el procedimiento en un Windows de prueba y generar el nuevo Centro apto para actualización desde 0.28.6; la firma Ed25519 del manifiesto actual es un requisito, no se debe falsificar.

**No publicar ni aplicar cambios sobre el motor de la PC real hasta pasar esas validaciones.**
