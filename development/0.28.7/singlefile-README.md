# VOLVÉ 0.28.7 — un solo EXE: piloto (NO INSTALAR)

El paquete de fuentes `singlefile-src.tar.xz` implementa un ensamblador en Go capaz de incorporar al mismo Windows PE ocho componentes firmados de VOLVÉ. También contiene una herramienta que inspecciona el EXE sin extraer ni ejecutar componentes. **No instala nada**: el bootstrapper solo acepta `--verify-bundle`.

SHA-256 de las fuentes: `01294e1d5ce51928098d30bd90f04b7979e1764993d4b419c66489b67676e215`.

El ensamblador exige la lista de ocho componentes y el manifiesto Ed25519 verificado por el módulo `unifiedbundle`; posteriormente comprueba ZIP, nombres, SHA-256, tamaños, versiones y firma. Rechaza paquetes incompletos, sobreescrituras de salida y corrupción de los bytes anexados. El código reconoce la posición del tráiler anterior a una posible tabla de certificados PE, **pero NO valida Authenticode**: en producción será obligatorio WinVerifyTrust.

Las pruebas y claves utilizadas hasta ahora son **sintéticas de laboratorio**. El código compila para Windows x64, pero todavía falta confirmar la ejecución del PE en GitHub Actions Windows real. No se distribuye como instalador.

FALTAN: integrar las fuentes privadas del instalador previo, la firma editorial auténtica del motor, verificaciones WinVerifyTrust, operación transaccional con permisos NTFS y watchdog SYSTEM persistente, desinstalador operativo, actualización 0.28.6 -> 0.28.7, reinicio persistente y rollback validado.

PR DRAFT / NO MERGE / NO RELEASE. La aceptación productiva del actualizador continúa 65/100 y el motor no está autorizado para distribución.
