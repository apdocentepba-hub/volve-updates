# VOLVÉ 0.28.7 — Criterios de cierre del paso 2/8

**Objetivo del paso 2:** disponer de una ruta de migración **implementada, verificable y reversible** desde el motor DNS que acompaña al Centro 0.28.6 hasta un motor administrado actualizado, sin reinstalación. El paso 2 **no es un permiso de publicación** ni de modificación de una PC ajena. Los pasos posteriores incluyen recuperación automática completa, ensayos de protección, migración controlada y distribución estable.

## Evidencias ya presentes en el piloto

- Respaldo local del ejecutable anterior y XML SYSTEM, hash/tamaño verificables y NTFS con propietarios y DACL protegidos.
- Validación de candidato y permiso editorial con Ed25519, contra las huellas exactas del motor anterior, su tarea y el candidato nuevo. **Solo hay firmas efímeras de CI; no un permiso editorial real publicado.**
- Contrato de transacción con preflight, staging, reconfirmación, prueba DNS/Internet y rollback en contexto independiente.
- Watchdog Windows independiente: restauración comprobada con **tareas CI descartables**, no con la tarea real.
- Journal durable de dos archivos create-only con nonce y terminal hash-bound, auditado desde otro proceso.
- Auditoría read-only `--audit-resident-chain <INSTALL-ROOT>` que exige coherencia entre respaldo, journal pendiente y bytes del motor instalado; no inicia tareas ni cambia DNS. Commits piloto: `60c62eaa`, `c3875fbc`, `7f0f2c3c`, `dd46945c`, `c1f2ca9b`, `1a4e33b3`. Su aceptación depende de las pruebas del commit final, no de runs antiguos.

## Condiciones para poder marcar PASO 2 CERRADO

- [ ] **A. Identidad editorial legítima.** Obtener un permiso de migración firmado con la clave editorial correcta que corresponda al hash **real** del ejecutable heredado y al candidato verificable. Sin inventar la versión histórica del motor ni sustituir por la clave efímera de CI.
- [ ] **B. Recuperación independiente productiva.** Implementar el recuperador SYSTEM para la tarea exacta `VOLVE-DNS-SERVER-0270`, con control explícito de tarea, binario, permisos NTFS, journal protegido y recuperación si desaparece el Centro. Registrar y verificar el watchdog **antes** de cambiar la tarea. No eliminar el bloqueo productivo actual sin esta condición.
- [ ] **C. Controlador Windows de migración.** Integrar un driver real con los contratos `SignedLegacySwitchDriver` y `ManagedSwitchDriver`, bloqueos de concurrencia y pinning del candidato; firma y permisos revalidados inmediatamente antes del switch; ejecución, sondeos locales y de Internet y rollback ante fallos.
- [ ] **D. Ensayo adverso repetible.** Probar actualizaciones con interrupción/kill del actualizador, candidato corrupto, permisos alterados, tarea SYSTEM sustituida, reinicio durante el cambio y caída DNS/Internet; nunca declarar recuperado sin pruebas efectivas de DNS y conectividad.
- [ ] **E. Reinicio Windows real.** Probar en una **VM Windows persistente** la secuencia `preparar -> cambiar -> reiniciar -> detectar el journal -> recuperar o confirmar -> comprobar DNS IPv4/IPv6 puerto 53` sobre **la misma VM**, con evidencia del evento real de boot. GitHub-hosted Windows jobs no cumplen por sí solos esta condición.
- [ ] **F. Revisión y autorización de cierre.** Cero pruebas críticas rojas, auditoría de seguridad, rollback explicado y artefacto candidato trazable. Aun con paso 2 aprobado, `main`, `stable.json` y `motor-stable.json` no se publican hasta las etapas previstas de entrega.

## Bloqueo actual y siguiente acción

La **brecha principal** es B+C: todavía **no existe** el driver que efectivamente conmuta el motor real junto a un watchdog productivo capaz de revertirlo. El código incluye una barrera explícita que rechaza `VOLVE-DNS-SERVER-0270` en `switchVerifiedMotorTaskAction`. **Debe permanecer activa** hasta demostrar B, C, D y E con autorización. El siguiente desarrollo prioritario es implementar y verificar el adaptador SYSTEM watchdog y el driver **en un laboratorio aislado**, sin desproteger ni alterar el VOLVÉ 0.28.6 instalado.

**No realizado:** migración real del motor del usuario, firma editorial de producción, publicación de motor estable y prueba de reboot persistente.
