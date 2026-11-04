# VOLVÉ 0.28.7 — auditoría de propiedad, solo lectura

**Este módulo público NO desinstala nada.** Sus verificaciones de recibos, hashes, tareas SYSTEM, archivos y DNS se emplean como controles de integridad y diagnóstico. No eliminan procesos, archivos, políticas, tareas, servicios ni configuraciones DNS.

**Política del propietario (04/11/2026):** el único desinstalador/reparador con capacidad de retirada se reservará al propietario del proyecto. Debe desarrollarse y mantenerse **fuera del paquete público, del sitio web, de los releases y de los artefactos públicos de CI**. No se incluye en `VOLVE_Setup.exe` ni en actualizaciones descargadas por usuarios.

Una eventual herramienta privada exigirá consentimiento explícito del propietario, autenticación independiente, verificación de procedencia, identidad de procesos/tareas, respaldo original de DNS y XML SYSTEM, journal durable, exclusión exclusiva y recuperación probada. **No existe todavía un desinstalador privado operativo ni se ha implementado aquí permiso para desinstalar.** Es indispensable una vía de reparación segura ante incidentes de red y pérdida de conectividad.

En la PC con 0.28.6 siguen presentes las tareas heredadas `VOLVE-CATALOGO-0230`, `VOLVE-DNS-RESCUE-0270` y `VOLVE-DNS-SERVER-0270`. El revisor responde `STOP_LEGACY_0286_PROTECTION_PRESENT`; no modifica la instalación.

Las pruebas de este paquete emplean claves efímeras y no otorgan firmas editoriales productivas, ni autorización de release o retirada. La protección frente a desinstalación convencional no puede prometer invulnerabilidad ante administradores de Windows, reinstalación del SO o acceso físico.
