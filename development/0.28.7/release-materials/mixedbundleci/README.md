# VOLVÉ 0.28.7 — integración de archivos reales al paquete (CI, NO RELEASE)

Este módulo reconstruye una **versión inactiva para laboratorio** a partir de materiales identificados y verificados:

| Función | Origen del archivo | Estado |
|---|---|---|
| Centro + actualizador | Compilación real Windows del código auditado | Archivo real, sin firma editorial de distribución |
| Watchdog independiente | Compilación real Windows del código auditado | Archivo real, sin firma editorial de distribución |
| Motor DNS | Release histórica v0.28.7, SHA-256 y tamaño exactos | Candidato histórico; **no aprobado para nueva instalación** |
| Manifiesto del motor | Firma editorial histórica comprobada previamente en el workflow | Archivo histórico real |
| Firma del motor | Firma editorial histórica comprobada previamente en el workflow | Archivo histórico real |
| Políticas de navegador | **Marcador sintético de CI** | NO implementado como insumo productivo |
| Catálogo completo | HaGeZi Gambling Full oficial, commit `81bbd1b9009893d65358146b23282647634c26be`, blob Git `096ce47515721f7aac2ce8138fb5b421aa6fb1e1` | Fuente original exacta, **pendiente de verificar compatibilidad del motor y obligaciones GPL-3.0 para distribución** |

La herramienta exige un informe de auditoría independiente con dos compilaciones Windows verificadas y un candidato histórico autenticado; compara hash y tamaño de las tres piezas ejecutables, valida PE32+ en el Centro y watchdog y rechaza que la auditoría dé permiso de instalación, publicación o cambios de DNS/tareas. Solo entonces crea el conjunto de siete funciones, lo firma con una clave Ed25519 **efímera y exclusiva del ensayo**, verifica los siete hash y copia la versión inactiva bajo un mutex de Windows.

Los seis archivos con fuente real se contrastan mediante SHA-256 al finalizar; el catálogo se conserva byte a byte sin reinterpretar sus reglas wildcard y exige identificación por commit, blob SHA-1 Git, tamaño exacto (11.040.215 bytes), al menos 400.000 reglas válidas y comprobación independiente en Go. La política de navegador que aún falta **nunca se silencia ni se considera completa**. Su contenido está marcado `never_install` / `NEVER-INSTALL`. No se exporta ni conserva la clave privada de CI, y los artefactos de CI no se suben como release.

**Limitaciones y requisitos pendientes:** las cinco piezas reales no equivalen a cinco componentes autorizados; hay cero aprobaciones productivas. Falta la política real de los navegadores, validación funcional del catálogo completo en el motor y cumplimiento de su licencia GPL-3.0, identidad y firma productiva del Centro y watchdog, autorización firmada de migración, preparación bajo SYSTEM/ACL NTFS, instalación transaccional, verificación luego de reinicio y rollback en la VM persistente. El desinstalador privado queda fuera del bundle.
