# VOLVÉ 0.28.7 — Hito 6: autorización editorial de migración

**Fecha:** 31 de octubre de 2026 (Argentina). **Rama:** `feature/motor-updater-0287-pilot`.

## Estado auditable

- **Progreso global:** 50% (5 de 10 puertas ya acreditadas). No es confiabilidad ni disponibilidad para instalar.
- **Progreso de esta puerta 6:** 50% del trabajo subdividido en cuatro controles; **0% acreditado al global** hasta completar los cuatro.
- **CI Windows y Linux aprobada:** [#41258366599](https://github.com/apdocentepba-hub/volve-updates/actions/runs/41258366599).
- **Entrega:** `development/0.28.7/inapp/legacy_publisher_review_packet.go` y pruebas. Se incluyen en `apply_overlay.go`; no se instaló ni publicó una actualización.

### Cuatro controles del hito 6

| Control | Criterio comprobable | Estado |
| --- | --- | --- |
| 6.1 | Identificar el motor anterior por bytes, SHA-256 y recibo original de rollback coherente, sin inferir versión | Código y pruebas de laboratorio aprobados |
| 6.2 | Verificar firma Ed25519, hash y compatibilidad del candidato; construir evidencia de revisión **sin firma privada** | Código y CI Windows/Linux aprobados |
| 6.3 | Obtener evidencia real del motor **instalado por el usuario** y cotejar la clave pública fijada del editor, sin usar huellas ficticias | Pendiente: no hay acceso al Windows instalado ni hay release nuevo firmado |
| 6.4 | Emitir/publicar permiso **real** de migración por el editor legítimo y validar la transición exacta; prohibir firma CI como sustituto | Pendiente: firma editorial auténtica no disponible |

### Contrato nuevo: revisión sin permiso

`BuildLegacyPublisherReviewPacketReadOnly` comprueba que el motor anterior instalado coincide **dos veces** con el respaldo local protegido; valida el XML SYSTEM respaldado, la firma del motor candidato, la versión mínima de Centro y el preflight de tarea/rescate/DNS. También vuelve a verificar la salud y los bytes antes de devolver el expediente. Los campos incluyen hashes y tamaños originales, hash del XML de tarea, versión/hash/tamaño del candidato, versión de Centro observada y huella SHA-256 **de la clave pública**.

El componente se marca exactamente `dns-engine-migration-review-only`, disposición `REVIEW_ONLY_UNSIGNED_NOT_A_PERMIT`. No contiene versión histórica supuesta, rutas personales ni clave privada; no altera motor, backup, DNS, tareas ni registro. **Este objeto no es un permiso de migración ni debe usarse como uno.**

Los tests cubren firmas ausentes, otros editores, bytes de motor alterados, respaldo corrupto, falta de respaldo, ACL padre/archivo insuficiente, preflight fallido en primera o segunda lectura, Centro incompatible, recibo de motor ya administrado, cancelación y rechazo de expediente sin firma como autorización.

### Bloqueos antes de actualizar un Windows real

1. El **editor legítimo**, con la clave privada guardada **fuera del repositorio y de CI**, debe cotejar el expediente de los bytes realmente instalados y firmar el JSON de permiso real `dns-engine-legacy-migration` correspondiente a esos hashes, la tarea `VOLVE-DNS-SERVER-0270`, el XML original y el candidato final.
2. Ese permiso debe pasar `VerifySignedUnversionedLegacyMigration` con la clave pública fijada del Centro. Un expediente sin firma o firmado con una clave temporal de pruebas jamás reemplaza esto.
3. Mantener la barrera productiva: faltan watchdog SYSTEM autónomo y seguro, controlador transaccional, reboot real en la **misma VM Windows persistente**, y pruebas de reversión adversas. **No cambiar ni detener el motor instalado** ni publicar stable.json/motor-stable.json.
4. Ningún CI GitHub-hosted equivale a un reboot persistente ni a pruebas del equipo del usuario. La verificación sobre el equipo real tiene que ser de solo lectura antes de autorizar una intervención.

### Próximo avance de ingeniería independiente de la firma

Desarrollar el adaptador aislado que obtiene la identidad **real** de tarea SYSTEM y del ejecutable instalado, valida el recibo bajo ACL y pasa esos valores a la función de revisión. Primero ejecutarlo en VM y con guardas de no-mutación; no integrarlo al botón de actualización hasta tener permiso editorial y ensayo de reboot.

**Importante:** esta puerta sigue ABIERTA; el 50% se refiere al progreso de las tareas de laboratorio, no a la capacidad de actualizar automáticamente.
