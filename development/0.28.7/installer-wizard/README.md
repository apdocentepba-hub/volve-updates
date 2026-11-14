# VOLVÉ 0.28.7 — Asistente de instalación, VISTA PREVIA

**Estado:** prototipo real de interfaz Windows con NSIS / Modern UI 2.
**NO INSTALA, NO BLOQUEA, NO REGISTRA, NO CONFIGURA EL DNS.**

## Flujo que se puede probar
1. Bienvenida.
2. Lectura y aceptación explícita de términos.
3. Consentimiento granular: DNS, tareas SYSTEM, políticas de navegador y descargas de reglas firmadas, más advertencia de compromiso.
4. Duración del compromiso: 7, 30 o 90 días.
5. Resumen y última aceptación de que es una demo inactiva.
6. Página de verificación sin escritura.
7. Finalización, con advertencia de protección no activada.

El código de la sección NO contiene instrucciones File, Exec, WriteRegStr,
CreateShortCut, RegisterTask, ni invoca PowerShell o netsh. El proceso pide
`asInvoker`: la demo **no eleva a administrador**.

## Instalador único productivo futuro: contrato exigido

Se generará un único `VOLVE_Setup.exe`, con todos los componentes firmados
validados contra un manifiesto editorial y Authenticode real. En el momento
de activación se obtendrá UAC, recién después de informar y solicitar
consentimiento. Debe admitir instalación nueva o migración segura, crear
snapshot original completo, verificar capacidad de restauración autónoma,
activar doble pila IPv4/IPv6, verificar bloqueos y dominios permitidos, y
volver atrás si falla cualquier comprobación. Mientras esos criterios no
pasen, **debe quedarse inactivo y rechazar activar protección**.

El actualizador se separa de la UI y del motor, verifica Ed25519 / versiones,
descarga por HTTPS, actualiza catálogos sin cambiar protecciones activas y
restaura versiones anteriores ante fallas. No debe tratar paquetes no
firmados ni descargar código de sitios externos arbitrarios.

## Autoexclusión, retiro y soporte

Inspiración verificable: BetBlocker permite compromisos por plazo o calendario,
y períodos de reflexión después de una exclusión prolongada. Para VOLVÉ:

- Inicio con fecha, plazo, firma del servicio local y recibo protegido.
- Antes de vencer: no ofrecer un botón de "desactivar ya" que ignore compromiso.
- Retiro extraordinario: solicitud + autenticación y autorización firmada por
  instalación + nonce único + vigencia limitada + restauración DNS/hosts/tareas.
- La autorización debe consumirse atómicamente, auditarse sin datos personales
  innecesarios y no funcionar para otra PC ni para un segundo uso.
- Reparación y retiro de emergencia con operación local autorizada aun sin
  Internet. Ninguna instalación debe dejar a alguien sin conexión por diseño.
- La herramienta privada del propietario está **fuera de este paquete público**.
- Un administrador de Windows conserva capacidad legítima de reparación;
  nunca prometer invulnerabilidad absoluta o imposibilidad de retirar software.

## Catálogo: pipeline propuesto

1. Fuentes de dominios existentes y el catálogo propio VOLVÉ, como una
   fuente adicional con procedencia y fecha.
2. Normalización IDNA, deduplicación, validación de hostnames, revisión de
   falsos positivos, lista de excepciones de seguridad y DNS esencial.
3. Empaquetado determinista con recuento de entradas y SHA256, manifiesto
   firmado Ed25519 y versiones monotónicas.
4. Descarga segura con rollback y controles de salud DNS independientes.
5. Métricas agregadas de reglas obsoletas, sin enviar URL consultadas.

No mezclar listas de procedencia desconocida o bloquear toda Internet ante
errores de sincronización.

## Criterios de aceptación productiva pendientes

- E2E real Windows de instalación, actualización, fallo, rollback tras reboot.
- Firma Authenticode de producción (el certificado sintético de CI NO sirve).
- Backend transaccional SYSTEM vinculado al recibo DNS firmado persistente.
- Desinstalación/reparación autorizada con rechazo de replay y prueba offline.
- Bloqueo probado en varios navegadores, IPv4/IPv6, DoH/VPN, conectividad.
- EULA definitivo, revisión de accesibilidad, test de uso con consentimiento.

No publicar ni distribuir la demo como si protegiera al usuario.
