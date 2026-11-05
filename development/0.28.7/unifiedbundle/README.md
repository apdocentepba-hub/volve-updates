# VOLVÉ 0.28.7 — contrato del paquete público (sin desinstalador)

**NO RELEASE.** Este verificador exige exactamente siete componentes en el futuro `VOLVE_Setup.exe`: Centro + actualizador, motor DNS, manifiesto y firma del motor, watchdog SYSTEM, políticas de navegadores y catálogo Full.

**El desinstalador del propietario es un producto separado, privado y no distribuible.** Está prohibido incluir `VOLVE_Uninstall.exe`, un removedor renombrado, claves de recuperación o funciones de retirada en el Setup público. La verificación falla si aparecen entradas adicionales, incluso con un manifiesto firmado.

Los siete componentes deben tener nombres, versión, plataforma, tamaños y SHA-256 exactos en `manifest.json` autenticado mediante `manifest.ed25519`. Se requiere clave pública editorial fijada externamente. El paquete no permite rutas ajenas, faltantes, duplicados, cambios de bytes ni enlaces simbólicos.

`go test ./...` prueba casos válidos y adversariales con firmas sintéticas; no autoriza ninguna distribución, instalación, cambio de DNS ni tareas SYSTEM. La instalación transaccional, las firmas reales y la recuperación tras reinicio siguen pendientes.

**Importante:** el archivo histórico `singlefile-src.tar.xz` todavía arma un fixture de ocho piezas en CI, únicamente para laboratorio. No satisface el nuevo contrato público y **no puede convertirse en release** sin reconstruirlo, excluir el removedor y revalidarlo de extremo a extremo.
