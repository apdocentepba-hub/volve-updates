# VOLVÉ motor DNS 0.28.7 — paquete editorial preparado (NO INSTALAR)

La pareja de archivos **manifiesto + firma** fue producida sin poner la clave privada en el repositorio. Autentica una copia renombrada **byte por byte** de la versión oficial `VOLVE_0_28_7_CENTRO.exe`, tamaño 18.168.832, SHA-256 `e451b6289116636986ddd67b39dc15f02e471ebde7be9508b38d7bcb0155b414`.

**El ejecutable original no se agrega a Git.** El workflow efímero descarga la release oficial y comprueba SHA-256 antes de renombrarlo temporalmente como `VOLVE_DNS_Motor_0_28_7.exe` para verificar la firma con la API real `motorupdate.VerifyStaged`.

La URL del manifiesto representa el futuro asset, **NO existe todavía como paquete publicado**. El canal `releases/motor-stable.json` **no está habilitado**. Esta carpeta no constituye permiso de migración ni atestación de un motor heredado. Queda prohibido usar estos archivos como sustituto de respaldo, watchdog SYSTEM real, autorización firmada del motor anterior o prueba de reinicio con recuperación.

No ejecutar, instalar ni copiar el paquete sobre un motor activo. No publicar en `main` ni en una release sin superar los controles productivos y la autorización correspondiente.
