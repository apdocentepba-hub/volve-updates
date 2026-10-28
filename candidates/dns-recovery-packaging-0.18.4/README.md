# VOLVÉ 0.18.4 — integración del rescatador DNS (solo desarrollo)

**28/10/2026 — NO INSTALAR; NO PUBLICAR `stable`.**

En el código privado se integró `VOLVE_DNS_Recovery.exe` como quinto componente obligatorio del empaquetador único, con comprobaciones de tamaño/arquitectura/hash antes y después de copiar. Se añadió una comprobación en modo lectura de la instalación `components-only` 0.18.0 basada en su estado y cuatro huellas SHA-256 originales, y código de preparación de un repositorio de recuperación con ACL Windows restringida a SYSTEM y Administradores.

**Validación:** suites Go y `-race` ejecutadas en Linux; motor legado aprobado; `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...` aprobado; compilación del instalador GUI y de las pruebas Windows (sin ejecución en Windows) correcta. Cinco de cinco componentes incrustados verificados.

**Limites:** sigue siendo un instalador de componentes sin protección DNS activa. No actualiza la instalación 0.18.0 existente ni activa el rescatador, motor o actualizaciones remotas. No se probó el controlador de adaptadores ni el rollback real en Windows. No se modificó la PC del usuario.

**Respaldo privado:** [VOLVE_0184_INTEGRACION_RESCATE_FUENTES_NO_INSTALAR.zip](https://drive.google.com/file/d/19tGcBJZNM-DCXVVxUTm8V_q9ffm8XwV-/view) (41.219.072 bytes; SHA-256 `f38edd8ec09e08e4afafefcd64c1b0a28667436624d05635595c564c7928c99d`).

**Próximo paso técnico:** migración transaccional de 0.18.0, activación con guardián independiente y pruebas end-to-end en Windows real antes de declarar un único `VOLVE_Setup.exe` completo.
