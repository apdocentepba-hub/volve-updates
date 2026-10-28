# VOLVÉ 0.18.9 — inventario IPv4 y validación segura del DNS (28/10/2026)

**Laboratorio. No instalar. No publicar stable.**

Se ajustó el código del controlador Windows para ignorar interfaces físicas sin pila IPv4 en la selección del adaptador principal y rechazar configuraciones con cero o más de un adaptador físico IPv4. Se normalizó el GUID con/sin llaves para comprobar la identidad en las operaciones de activación, consulta y reversión; ningún cambio usa solamente el nombre visual del adaptador.

En el entorno de desarrollo pasaron las suites principales Go, de concurrencia para DNS/migración, pruebas del motor legado y validaciones de compilación cruzada Windows. Se compiló `VOLVE_DNS_Recovery` de laboratorio, sin ejecutarlo en el Windows del usuario.

Pruebas Windows **aprobadas antes**: tareas de rescate SYSTEM de inicio y repetición de 5 minutos y auditoría DNS de solo lectura. Se añadió un workflow para probar la captura de configuración y la recepción de UDP `127.0.0.1:53` sin modificar adaptadores: [Windows DNS capture and loopback smoke](https://github.com/apdocentepba-hub/volve-updates/actions/workflows/volve-windows-capture-check.yml). La ejecución de GitHub Actions terminó con éxito (Windows Server 2025, `success`): [ver resultado 40780130282](https://github.com/apdocentepba-hub/volve-updates/actions/runs/40780130282). Esta prueba de captura y UDP loopback NO modifica los adaptadores DNS ni valida una instalación completa.

[Respaldo de fuentes 0.18.9](https://drive.google.com/file/d/11jBNGpZKSXvPmtEf2ZfyasbU6Eti1WzD/view) — SHA256 `383f56c5bc6800f93b02234999225bab227070e511752c702da9239f1a7be7df`.

**Persisten los bloqueos fundamentales:** ensayo de activación, fallo provocado y restauración DNS en Windows aislado; validación de migración 0.18.0 en Windows; actualización firmada del motor activo y setup final. No se tocó ni instaló nada en el equipo del propietario.
## Auditoría independiente del respaldo de fuentes

- Se comprobó el ZIP privado `VOLVE_0189_CORRECCION_INTERFAZ_IPV4_FUENTES_NO_INSTALAR.zip` y su código Go.
- En una extracción limpia, `go test ./... -count=1` inicialmente falla en las dos pruebas de `cmd/volve-setup`: el ZIP de código no trae los cinco binarios embebidos que exige el manifiesto. Esto es un requisito de generación del paquete, no una prueba del motor DNS.
- Al ejecutar `python scripts/build_singlefile_0187.py` se generaron los cinco binarios Windows amd64 y el instalador de componentes beta; después `go test ./... -count=1` completó todas las suites principales. También aprobaron `go test -race ./dnsactivation ./setupinstall ./winsetup -count=1`.
- **Bloqueo de versión:** el script y `setuppackage.Version` permanecen en `0.18.7`; el archivo resultante NO debe denominarse instalador `0.18.9` ni difundirse como entrega final. La GUI sigue sin activar DNS y `ReadyForInstallation=false`.
- No se ejecutó el instalador sobre Windows ni se probó el circuito completo de activación, fallo forzado, recuperación o actualización firmada del motor. `stable` sigue sin activarse.
