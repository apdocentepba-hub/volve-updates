# VOLVÉ — Guía para habilitar aportes voluntarios
**Actualización:** 29/10/2026 · **Estado:** guía de configuración, cobros NO habilitados todavía.

## Objetivo
Que quienes quieran apoyar a VOLVÉ puedan hacerlo **por decisión propia y sin condicionamientos**, para sostener el desarrollo, las pruebas del software, la infraestructura, la prevención, el mantenimiento y, cuando corresponda, la remuneración transparente del trabajo. El programa seguirá siendo gratuito y su versión estable **todavía no está disponible**.

**Identidad institucional:** VOLVÉ es un proyecto independiente, **no una asociación civil, fundación ni ONG constituida**. No presentar los aportes como fiscalmente deducibles, ni emitir certificados de donación de una ONG. En Argentina ARCA limita la deducibilidad a receptores que cumplen condiciones específicas. Antes de habilitar recaudación pública, consultar al contador el encuadre tributario de aportes recibidos a una cuenta personal o de actividad económica.

## Opciones recomendadas
| Canal | Para quién | Ventajas | Precauciones |
| --- | --- | --- | --- |
| **Cafecito** | Aportes voluntarios sencillos | Perfil propio con descripción de VOLVÉ y botón de apoyo | Comisiones del servicio y del procesador se muestran en la plataforma; revisar medios habilitados y costos antes de activar |
| **Mercado Pago: Tu Link o Link de pago** | Aportes con distintos medios de pago | Enlace de cobro compartible en sitio y redes, sin programar API | Costos y disponibilidad dependen de provincia, medio elegido y plazo de liberación; comprobar si Tu Link permite al aportante elegir monto en tu cuenta |
| **Transferencia bancaria o a billetera (opcional)** | Quienes prefieran transferencia | Permite informar un alias público para recibir aportes | Se muestra titular y otros datos según el sistema; revisar privacidad y conciliación; nunca publicar claves, CVU privados de terceros ni capturas de cuenta |

**Orden sugerido:** empezar con Cafecito y Mercado Pago; añadir transferencia solo si la cuenta receptora es apropiada para el proyecto. No es necesario montar una pasarela con API ni un backend para empezar.

## Paso 1: crear y configurar Cafecito
1. Abrir **https://cafecito.app/** e ingresar con una cuenta propia; completar los datos que solicite la plataforma.
2. Elegir un identificador y nombre visual claros como **VOLVÉ — Prevención de apuestas online** (sujeto a disponibilidad; **no inventar que la cuenta ya existe**).
3. Usar una descripción breve, por ejemplo:
   > VOLVÉ es un proyecto argentino independiente que desarrolla herramientas gratuitas para sumar barreras voluntarias frente a las apuestas online y difunde recursos de ayuda. El software sigue en desarrollo. Tu aporte voluntario ayuda a sostener desarrollo, infraestructura, prevención y trabajo técnico. No es obligatorio ni otorga ventajas sobre otras personas.
4. Desde la sección **Pagos**, configurar el medio de cobro que la cuenta ofrezca, por ejemplo Mercado Pago. Completar verificaciones de identidad o datos bancarios **solo en la web o app oficial**, nunca por mensajes.
5. Establecer el importe de cada «cafecito» y revisar, **antes de publicar**, la comisión de Cafecito y la del procesador; no publicar una cifra fija sin consultar condiciones vigentes.
6. Revisar el perfil desde una ventana privada, confirmar que explique VOLVÉ, que el receptor sea correcto y que no exponga datos personales que no quieras hacer públicos.
7. Copiar la **URL exacta del perfil real**, y recién entonces incorporarla a `site/src/config/site.ts` en `donations` → `cafecito`. No crear enlaces hipotéticos.

Fuentes oficiales: https://cafecito.app/faq/como-usar-cafecito · https://cafecito.app/faq/como-configurar-mis-medios-de-cobro · https://cafecito.app/faq/comisiones-costos-y-precios · https://cafecito.app/faq/como-compartir-mi-perfil · https://cafecito.app/faq/como-usar-botones-de-cafecito

## Paso 2: crear un enlace de Mercado Pago
1. Iniciar sesión en **https://www.mercadopago.com.ar/herramientas-para-vender/link-de-pago** con la cuenta que corresponda a VOLVÉ.
2. Buscar **Tu Link**, si está disponible para esa cuenta: un enlace único donde la persona puede indicar un monto. Si no está disponible, usar **Link de pago** con un importe fijo por enlace o crear opciones de importe distintas.
3. Descripción sugerida: **«Aporte voluntario para sostener VOLVÉ — proyecto gratuito de prevención»**. No presentarlo como venta de una licencia, consulta médica ni suscripción.
4. Seleccionar medios de pago y plazo de acreditación; comprobar el costo mostrado en tu cuenta (pueden aplicar comisiones, retenciones e impuestos) y evitar habilitar cuotas que impliquen costos sin revisar.
5. Guardar y copiar la **URL real, pública y HTTPS**. Probar la página antes de recibir aportes (importe, identidad del receptor, descripción y opciones disponibles).
6. Solo después de validar el link, incorporarlo a `site/src/config/site.ts` en `donations` → `mercadopago`. Si necesitás varios importes, crear botones separados con el texto y enlace reales, sin duplicar ni confundir los montos.

Fuente: https://www.mercadopago.com.ar/herramientas-para-vender/link-de-pago
Documentación de opciones de cobro: https://www.mercadopago.com.ar/developers/es/docs/getting-started

## Paso 3: transferencia (solo si conviene)
1. Definir una **cuenta propia o vinculada legalmente al proyecto**; verificar que su titular visible y tratamiento impositivo sean adecuados.
2. Usar un **alias público dedicado**, si decidís habilitarlo, e indicar el nombre del titular para que la persona verifique antes de transferir.
3. No colocar DNI, CUIT personal, correo privado, clave bancaria, tokens, códigos de acceso, ni capturas con saldos en el sitio.
4. Para que sea una opción funcional se necesita una sección de instrucciones y eventualmente un botón **«Copiar alias»**. La estructura actual `donations` usa URL o `null`, por lo que **el alias requiere adaptar la interfaz**, no escribir un alias en un campo `url` ni inventar un enlace.

## Paso 4: incorporar los botones al sitio
Web principal: https://volve-web.onrender.com/ · código en GitHub: https://github.com/apdocentepba-hub/volve-updates/tree/main/site

- Configurar **solo enlaces ya creados y comprobados** en `site/src/config/site.ts`.
- La página `/colabora` ya recorre `siteConfig.donations` y muestra botones activos cuando el link es HTTPS. Los métodos con `url: null` permanecen como **«próximamente»**. Mantener ese comportamiento hasta completar los pasos.
- La llamada **«Colaborá con VOLVÉ»** ya aparece en la portada y menú, además de sectores de educación y ayuda; los botones deben dirigir primero a `/colabora` para informar sobre voluntariedad y transparencia.
- Agregar, si sirve, 2–3 montos sugeridos y una opción de importe libre **solo cuando el proveedor lo permita y el destino esté verificado**. Jamás solicitar tarjetas o claves en la página propia: el pago debe realizarse en el proveedor oficial.
- Mantener siempre un camino no monetario: compartir por WhatsApp, difundir prevención en Instagram, ofrecer habilidades o información.

## Paso 5: control de calidad y publicación
- [ ] Verificar que cada botón lleve al perfil o checkout oficial correspondiente y no a un enlace roto.
- [ ] Comprobar el titular receptor, importe, comisión, datos expuestos y condiciones visibles sin capturar pagos de terceros.
- [ ] Hacer **un aporte de prueba real y pequeño**, solo con aprobación del titular, y verificar acreditación/comisión/posible devolución; no iniciar pagos desde una automatización.
- [ ] Comprobar los enlaces en celular y computadora, también en modo privado.
- [ ] Verificar que la web siga destacando las vías de ayuda y que nunca obligue a donar.
- [ ] Compilar `site/` y comprobar Render `live`; Render está configurado con auto-deploy al repositorio `main`. Evitar commits innecesarios que consuman minutos.
- [ ] Hacer una revisión final de claridad, términos de uso, datos personales y encuadre impositivo con un profesional si se recaudan fondos de forma sostenida.

## Paso 6: rendición de cuentas y comunicación
Usar un apartado de **transparencia**, actualizado por mes, con:
| Mes | Aportes brutos | Comisiones/impuestos del procesador | Neto recibido | Gastos por categoría | Saldo |
| --- | ---: | ---: | ---: | ---: | ---: |
| AAAA-MM | — | — | — | — | — |

Categorías: infraestructura, desarrollo, prevención y difusión, mantenimiento y remuneración del trabajo si corresponde. No mostrar identidad, montos individuales ni mensajes privados de aportantes sin consentimiento. No atribuir a VOLVÉ la condición de ONG ni sugerir que el aporte es deducible en Ganancias. No prometer informes ya emitidos antes de que existan.

Referencia tributaria: https://www.arca.gob.ar/gananciasYBienes/ganancias/personas-humanas-sucesiones-indivisas/deducciones/deducciones-generales.asp

## Textos públicos propuestos
**Botón:** «❤️ Apoyá VOLVÉ» o «Colaborá con VOLVÉ».

**Texto breve:** «VOLVÉ es gratuito y sigue en desarrollo. Si querés, podés aportar voluntariamente para ayudarnos a sostener el proyecto. No es obligatorio, no desbloquea ninguna función y no reemplaza la ayuda profesional.»

**Texto de aclaración:** «VOLVÉ es un proyecto independiente. Los aportes son voluntarios y no otorgan beneficios exclusivos ni se presentan como donaciones deducibles de impuestos. Revisá siempre el destino del pago antes de confirmar.»

## Información necesaria para activar aportes en la web
La persona titular deberá proporcionar **solo** estos datos públicos:
- URL real de su perfil de Cafecito (si lo habilita).
- URL real de Mercado Pago «Tu Link» o Link de pago (si lo habilita).
- Si decide usar transferencia: alias público, titular visible y autorización expresa para publicarlos.
- Confirmación de que revisó costos, privacidad y encuadre fiscal.

**No pedir ni compartir contraseñas, códigos de verificación, access tokens de Mercado Pago, datos de tarjetas, capturas de documentos personales ni secretos**. Con URLs verificadas se puede actualizar la web desde GitHub y Render sin usar Lovable.
