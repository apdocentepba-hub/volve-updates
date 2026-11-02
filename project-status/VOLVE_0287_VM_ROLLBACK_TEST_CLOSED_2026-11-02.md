# VOLVÉ 0.28.7 - ensayo de recuperación en VM completado

Ensayo: 20261102000201. El operador confirmó Verify con PASS después de reiniciar Windows invitado. El JSON auditado registra evento 118,100,201,102, resultado 0, journal NO_ROLLBACK:restored y restauración cmd.exe /C exit 0.

El operador ejecutó Cleanup; resultado: CLEAN, ambas tareas descartables eliminadas; evidencia conservada en ProgramData.

Ensayo anterior: motor DNS completo de laboratorio inicia bajo SYSTEM después de reboot, DNS v4/v6 6/6 y TCP externo 2/2. La tarea DNS temporal también fue retirada.

Queda por demostrar actualización de ejecutable real de motor, autorización editorial y rollback del motor original con DNS+Internet tras reboot. Los dos ensayos aprobados son separados: no certifican la actualización productiva 0.28.6 a 0.28.7.

Indicador técnico de aceptación del actualizador: 65/100, sin cambios. No liberar motor-stable.json ni modificar el host.
