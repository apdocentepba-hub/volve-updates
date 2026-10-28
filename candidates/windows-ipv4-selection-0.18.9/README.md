# VOLVÉ 0.18.9 — inventario IPv4 y validación segura del DNS (28/10/2026)

**Laboratorio. No instalar. No publicar stable.**

Se ajustó el código del controlador Windows para ignorar interfaces físicas sin pila IPv4 en la selección del adaptador principal y rechazar configuraciones con cero o más de un adaptador físico IPv4. Se normalizó el GUID con/sin llaves para comprobar la identidad en las operaciones de activación, consulta y reversión; ningún cambio usa solamente el nombre visual del adaptador.

En el entorno de desarrollo pasaron las suites principales Go, de concurrencia para DNS/migración, pruebas del motor legado y validaciones de compilación cruzada Windows. Se compiló `VOLVE_DNS_Recovery` de laboratorio, sin ejecutarlo en el Windows del usuario.

Pruebas Windows **aprobadas antes**: tareas de rescate SYSTEM de inicio y repetición de 5 minutos y auditoría DNS de solo lectura. Se añadió un workflow para probar la captura de configuración y la recepción de UDP `127.0.0.1:53` sin modificar adaptadores: [Windows DNS capture and loopback smoke](https://github.com/apdocentepba-hub/volve-updates/actions/workflows/volve-windows-capture-check.yml). Aún no se confirmó el resultado de esa nueva ejecución.

[Respaldo de fuentes 0.18.9](https://drive.google.com/file/d/11jBNGpZKSXvPmtEf2ZfyasbU6Eti1WzD/view) — SHA256 `383f56c5bc6800f93b02234999225bab227070e511752c702da9239f1a7be7df`.

**Persisten los bloqueos fundamentales:** ensayo de activación, fallo provocado y restauración DNS en Windows aislado; validación de migración 0.18.0 en Windows; actualización firmada del motor activo y setup final. No se tocó ni instaló nada en el equipo del propietario.