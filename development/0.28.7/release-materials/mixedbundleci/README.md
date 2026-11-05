# VOLVÉ 0.28.7 — integración de archivos reales al paquete (CI, NO RELEASE)

Este módulo reconstruye una **versión inactiva para laboratorio** a partir de materiales identificados y verificados:

| Función | Origen del archivo | Estado |
|---|---|---|
| Centro + actualizador | Compilación real Windows del código auditado | Archivo real, sin firma editorial de distribución |
| Watchdog independiente | Compilación real Windows del código auditado | Archivo real, sin firma editorial de distribución |
| Motor DNS | Release histórica v0.28.7, SHA-256 y tamaño exactos | Candidato histórico; **no aprobado para nueva instalación** |
| Manifiesto del motor | Firma editorial histórica comprobada previamente en el workflow | Archivo histórico real |
| Firma del motor | Firma editorial histórica comprobada previamente en el workflow | Archivo histórico real |
| Políticas de navegador | Plan real generado desde el catálogo autenticado (Chrome, Edge, Firefox) | **772 valores definidos, no aplicados**; falta instalador transaccional, propiedad y prueba real en navegadores |
| Catálogo completo | HaGeZi Gambling Full oficial, commit `81bbd1b9009893d65358146b23282647634c26be`, blob Git `096ce47515721f7aac2ce8138fb5b421aa6fb1e1` | Fuente original exacta, **pendiente de verificar compatibilidad del motor y obligaciones GPL-3.0 para distribución** |

La herramienta exige un informe de auditoría independiente con dos compilaciones Windows verificadas y un candidato histórico autenticado; compara hash y tamaño de las tres piezas ejecutables, valida PE32+ en el Centro y watchdog y rechaza que la auditoría dé permiso de instalación, publicación o cambios de DNS/tareas. Solo entonces crea el conjunto de siete funciones, lo firma con una clave Ed25519 **efímera y exclusiva del ensayo**, verifica los siete hash y copia la versión inactiva bajo un mutex de Windows.

Los seis archivos con fuente real se contrastan mediante SHA-256 al finalizar; el catálogo se conserva byte a byte sin reinterpretar sus reglas wildcard y exige identificación por commit, blob SHA-1 Git, tamaño exacto (11.040.215 bytes), al menos 400.000 reglas válidas y comprobación independiente en Go. El séptimo componente es ahora una declaración reproducible de 256 sitios prioritarios/de muestreo por navegador y cuatro opciones de DNS-over-HTTPS. No instala directivas ni asegura que los navegadores las respeten; el instalador posterior deberá preservar las directivas preexistentes. Su contenido está marcado `never_install` / `NEVER-INSTALL`. No se exporta ni conserva la clave privada de CI, y los artefactos de CI no se suben como release.

**Limitaciones y requisitos pendientes:** las cinco piezas reales no equivalen a cinco componentes autorizados; hay cero aprobaciones productivas. Falta aplicar y verificar realmente las políticas de navegador sin sobrescribir claves ajenas, auditoría de navegador, cobertura del catálogo más allá de los dos dominios probados y cumplimiento de su licencia GPL-3.0, identidad y firma productiva del Centro y watchdog, autorización firmada de migración, preparación bajo SYSTEM/ACL NTFS, instalación transaccional, verificación luego de reinicio y rollback en la VM persistente. El desinstalador privado queda fuera del bundle.


## Plan deseado para Chrome, Edge y Firefox (NO APLICADO)

El archivo `VOLVE_Browser_Policies.json` se genera **a partir del archivo HaGeZi Full auténtico**, sin volver a descargar ni confiar en dominios arbitrarios. Incluye una lista de 256 dominios distintos, dos priorizados y los demás seleccionados mediante un muestreo determinístico y distribuido; **no se los presenta como los 256 sitios más frecuentes**.

La configuración contiene 772 valores propuestos: 256 `URLBlocklist` de Chrome, 256 de Edge y 256 `WebsiteFilter\\Block` de Firefox; además, `DnsOverHttpsMode=off` (REG_SZ) para Chrome y Edge, y `DNSOverHTTPS\\Enabled=0`/`Locked=1` (REG_DWORD) para Firefox. El contrato utiliza `HKEY_LOCAL_MACHINE` y conserva `REFUSE_OR_SKIP_EXISTING_UNOWNED_VALUES`. Todo contenido se rechaza si cambió el catálogo anclado, faltan dominios de comprobación, se excede el límite, hay duplicados, sintaxis host inválida o se agregan permisos de escritura/publicación.

La generación y el staging **no escriben en el registro de Windows**. No reemplazan entradas de otras aplicaciones ni contienen desinstalador. Pendiente: ejecutor privilegiado con consentimiento verificable, diario de propiedad y reversión, inspección de directivas existentes y comprobación de `chrome://policy`, `edge://policy` y `about:policies` en Windows VM persistente. El filtrado DNS masivo sigue siendo independiente.
