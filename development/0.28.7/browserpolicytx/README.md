# VOLVÉ 0.28.7 — motor de ensayo transaccional de políticas

Módulo de laboratorio puro Go: consume el esquema exacto de `VOLVE_Browser_Policies.json` generado desde catálogo autenticado. Requiere **772 valores** (Chrome, Edge y Firefox; 256 dominios por navegador y cuatro ajustes DoH), y rechaza planes incompletos, alterados o que afirmen permiso de instalación.

La interfaz `LabStore` es un almacén de ensayo, **no es el Registro de Windows**. `Rehearse` valida los valores y su ausencia previa, crea solo valores nuevos mediante una interfaz atómica y realiza reversión total en orden inverso incluso ante fallos de escritura. La comprobación posterior exige quedar sin valores.

### Límites

No demuestra restauración ante un corte de energía: aún no existe el journal NTFS persistente de políticas ni el driver de Registro de Windows bajo mutex SYSTEM. No ejecuta políticas en navegadores. No reemplaza comprobaciones del editor, integridad, estado del host ni la VM persistente. **No se permite publicar un Setup ni modificar Windows con este módulo.** El desinstalador propietario no forma parte del artefacto.
