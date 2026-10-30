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

## Lo que falta para una actualización del motor sin reinstalar

- Registrar y verificar la versión/identidad real del motor que está instalado (no deducir de nombre de archivo).
- Implementar el controlador Windows `motorupdate.SwitchDriver` con respaldos inmutables, tareas SYSTEM verificadas, motor versionado, validación de DNS IPv4/IPv6 y conexión externa.
- Conectar journal + watchdog independiente a este controlador; validar reversión durante fallos y cortes, incluidos rechazos de respaldos alterados.
- Publicar un asset oficial del motor y su manifiesto Ed25519 **sin incluir la clave privada en GitHub**.
- Verificar el procedimiento en un Windows de prueba y generar el nuevo Centro apto para actualización desde 0.28.6; la firma Ed25519 del manifiesto actual es un requisito, no se debe falsificar.

**No publicar ni aplicar cambios sobre el motor de la PC real hasta pasar esas validaciones.**
