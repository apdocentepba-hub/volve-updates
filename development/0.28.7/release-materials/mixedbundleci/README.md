# VOLVÉ 0.28.7 — integración de archivos reales al paquete (CI, NO RELEASE)

Este módulo reconstruye una **versión inactiva para laboratorio** a partir de los materiales que efectivamente existen:

| Función | Origen del archivo | Estado |
|---|---|---|
| Centro + actualizador | Compilación real Windows del código auditado | Archivo real, sin firma editorial de distribución |
| Watchdog independiente | Compilación real Windows del código auditado | Archivo real, sin firma editorial de distribución |
| Motor DNS | Release histórica v0.28.7, SHA-256 y tamaño exactos | Candidato histórico; **no aprobado para nueva instalación** |
| Manifiesto del motor | Firma editorial histórica comprobada previamente en el workflow | Archivo histórico real |
| Firma del motor | Firma editorial histórica comprobada previamente en el workflow | Archivo histórico real |
| Políticas de navegador | **Marcador sintético de CI** | NO implementado como insumo productivo |
| Catálogo completo | **Marcador sintético de CI** | NO implementado como insumo productivo |

La herramienta exige un informe de auditoría independiente con dos compilaciones Windows verificadas y un candidato histórico autenticado; compara hash y tamaño de las tres piezas ejecutables, valida PE32+ en el Centro y watchdog y rechaza que la auditoría dé permiso de instalación, publicación o cambios de DNS/tareas. Solo entonces crea el conjunto de siete funciones, lo firma con una clave Ed25519 **efímera y exclusiva del ensayo**, verifica los siete hash y copia la versión inactiva bajo un mutex de Windows.

Los cinco archivos de origen real se contrastan byte a byte mediante SHA-256 al finalizar. Las dos funciones sin material productivo **nunca se silencian ni se consideran completas**. Su contenido está marcado `never_install` / `NEVER-INSTALL`. No se exporta ni conserva la clave privada de CI, y los artefactos de CI no se suben como release.

**Limitaciones y requisitos pendientes:** las cinco piezas reales no equivalen a cinco componentes autorizados; hay cero aprobaciones productivas. Falta la política real de los navegadores, catálogo completo, identidad y firma productiva del Centro y watchdog, autorización firmada de migración, preparación bajo SYSTEM/ACL NTFS, instalación transaccional, verificación luego de reinicio y rollback en la VM persistente. El desinstalador privado queda fuera del bundle.
