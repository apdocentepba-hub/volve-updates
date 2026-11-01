# VOLVÉ 0.28.7 — Puerta 6: entrega editorial pendiente

**Estado verificado: NO APROBADA.** Última inspección: 01/11/2026.
**Aceptación global del programa: 50% (5/10 puertas).** Este documento no autoriza instalación.

## Comprobado en el repositorio

- En la consulta de GitHub Releases de `apdocentepba-hub/volve-updates` del 01/11/2026, la última release disponible es `v0.28.6` (prerelease, publicada 29/10/2026). Su asset público es `VOLVE_0_28_6_CENTRO.exe`.
- No se encontró una release oficial `v0.28.7` ni un asset `VOLVE_DNS_Motor_0_28_7.exe` con manifest y firma de producción.
- El verificador de migración ya requiere **DOS firmas independientes** de la clave editorial instalada: el manifest `.json` y `.sig` del candidato, y el permiso `.migration.json` y `.migration.sig` para el motor legado preciso.
- El ZIP de fuente, las pruebas y los binarios `VOLVE-CI-*` **NO constituyen** una release firmada ni autorización editorial.

## Qué generó esta etapa

Los nuevos `motorupdate.PrepareLegacyMigrationDraftReadOnly` y `DraftPermitBytesReadOnly` derivan un borrador canónico de permiso desde una inspección del motor en ejecución, un respaldo con ACL confiables y un candidato cuya firma ya fue verificada. La firma original del editor no está disponible para ese código; **nunca** se lee, copia, imprime o publica una clave privada. La verificación de Linux y Windows pasó en GitHub Actions #41342896493, con claves de laboratorio efímeras.

El borrador propone una vigencia de **24 horas** y contiene huellas SHA-256 del EXE original, XML de la tarea SYSTEM, candidato y clave pública editorial; excluye rutas locales del equipo. Permanece como `PUBLISHER_REVIEW_REQUIRED_UNSIGNED_NO_INSTALL_PERMISSION`, con indicadores `signature_present=false`, `migration_authorized=false` y `ready_to_switch=false`.

## Requisitos exactos para acreditar la puerta 6

1. **Candidato 0.28.7 auténtico:** compilar y revisar el motor de distribución desde fuente auditada. Firmar su manifest con la **clave privada original** correspondiente a `updaterPublicKey` del Centro ya instalado. Verificar localmente SHA-256, tamaño, versión `0.28.7` y `min_panel_version`. No publicar ni sustituir un release sin autorización del responsable.
2. **Paquete de identidad del origen:** obtener en el equipo que recibirá la migración un nuevo informe privilegiado, con tarea SYSTEM, proceso DNS v4/v6, EXE original, XML de tarea y respaldo NTFS íntegro. No reutilizar huellas de otra PC ni datos anteriores al cambio del motor.
3. **Emisión editorial por canal separado:** con el borrador y el candidato verificables, el responsable de la clave legítima revisa el destino y firma **el JSON exacto del permiso** con la clave original (Ed25519). El archivo de firma es Base64 estricto de 64 bytes de firma. **No introducir la clave privada en ChatGPT, el repositorio, logs, GitHub Actions sin protección adecuada ni archivos de diagnóstico.**
4. **Aceptación independiente:** verificar `.migration.json` y `.migration.sig` con `VerifySignedUnversionedLegacyMigration`, usando la clave pública fijada por el Centro instalado y un preflight Windows actual; probar que cambios de un byte, caducidad, firma ajena, motor distinto y ausencia del respaldo impiden la migración. Guardar evidencia auditada del cumplimiento, sin subir datos personales.

**No sustituir:** firmar con una clave nueva creada en CI, una huella SHA-256 suelta, una firma de GitHub Actions, un certificado no reconocido por el Centro o un paquete de revisión SIN firma real. Esos recursos no satisfacen la identidad editorial existente.

## Dependencias posteriores (hitos 7–10)

Incluso con puerta 6 aprobada, el controlador productivo permanece deshabilitado hasta tener watchdog independiente firmado y protegido, prueba tras **reinicio real de una VM persistente**, y migración completa 0.28.6 → 0.28.7 con rollback auditable y autorización de despliegue. Ninguna prueba `VOLVE-CI-*` o AtStartup disparada manualmente reemplaza el reboot real.

**Regla de avance:** sin las firmas auténticas y la comprobación en el equipo real, el hito 6 tiene **0% de crédito** y el total permanece en **50%**.
