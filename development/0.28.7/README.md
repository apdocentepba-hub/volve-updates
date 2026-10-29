# VOLVÉ 0.28.7 — Actualizador del motor DNS (piloto)

**NO INSTALAR NI PUBLICAR COMO RELEASE ESTABLE.** La versión operativa sigue siendo VOLVÉ 0.28.6 y el canal releases/stable.json permanece intacto.

El paquete completo se almacena en 10 bloques binarios dentro de development/0.28.7/complete-source-parts. El CI reconstruye el ZIP exacto, valida su SHA-256 antes de extraer y compila el programa con el motor antiguo incorporado. SHA-256 ZIP: 92b3536559151260375b17a64eedd009df8399e45460637208027b7ca0587ba5.

El ZIP de codigo liviano anterior fue publicado para revisión de texto, pero no contiene el ejecutable de motor heredado (requerido por go:embed). No usarlo para compilar el programa completo.

Nuevo: firma Ed25519 y SHA-256 del canal aislado de actualizaciones del motor, preparación segura en una carpeta de versión, comando --check-motor-updates y opción avanzada de solo lectura. Las pruebas de recuperación usan un controlador simulado.

**Todavía no existe controlador Windows real que cambie la tarea del motor y la restaure después de un fallo.** En consecuencia no se publica releases/motor-stable.json ni se toca la instalación actual.
