# VOLVÉ: integrar el directorio dentro de Lovable
Actualizado: 29 de octubre de 2026. **Pendiente de edición, no publicado en Lovable.**

## Proyecto original
- Editor: https://lovable.dev/projects/49ccf194-5633-4d7d-a58d-1606ef7e07ff
- Sitio: https://volve-proyecto.lovable.app/
- Directorio ya publicado mediante GitHub Pages: https://apdocentepba-hub.github.io/volve-updates/
- Datos fuente: https://github.com/apdocentepba-hub/volve-updates/blob/main/website/ayuda-pba.html
- Fuentes CSV: https://github.com/apdocentepba-hub/volve-updates/blob/main/website/directorio_pba_45_recursos.csv

## Cambios visibles que hay que priorizar
1. En `src/routes/index.tsx`, junto a los botones principales, agregar un CTA prominente: **📍 Centros y reuniones de ayuda** / **45 recursos gratuitos en Buenos Aires: teléfonos, direcciones, horarios y reuniones virtuales**.
2. Repetir el mismo acceso en `src/routes/ayuda.tsx` (debajo o junto al componente `HelpBox`).
3. En `src/components/SiteHeader.tsx` agregar **Centros y reuniones** en la navegación desktop y móvil.
4. **Objetivo final**: integrar un buscador completo **bajo el propio dominio de Lovable**, preferentemente con una ruta propia `/centros-y-reuniones`, importando datos revisados del directorio y ofreciendo fuente oficial por recurso. Como primera solución válida, el botón puede abrir la página publicada en GitHub Pages; no atribuir a Lovable contenido que todavía reside en GitHub.
5. No eliminar ayuda urgente; no tocar software, descargas en desarrollo, donaciones ni políticas de privacidad.

## Snippet provisional para un botón externo React/TSX
```tsx
<a href="https://apdocentepba-hub.github.io/volve-updates/"
  target="_blank" rel="noopener noreferrer"
  className="inline-flex items-center justify-center rounded-full bg-primary px-6 py-3.5 font-semibold text-primary-foreground">
  📍 Centros y reuniones de ayuda
</a>
```

## Instrucción puntual al agente de Lovable
«En el proyecto existente VOLVÉ, agregá de forma visible un botón "📍 Centros y reuniones de ayuda" en portada y sección Necesito ayuda, y un ítem "Centros y reuniones" en menú desktop/móvil. Enlazar por ahora a https://apdocentepba-hub.github.io/volve-updates/, que contiene 45 recursos de ayuda bonaerenses verificados. Después incorporar el buscador dentro de una ruta propia del mismo sitio, con fuente oficial por recurso y recordatorio de reconfirmar horarios antes de asistir. No modificar otros proyectos ni el instalador. Compilar, desplegar y verificar el cambio de la web publicada».

## Estado de edición
El conector Lovable rechazó la edición el 29/10/2026 por **créditos agotados del workspace**. NO comprar créditos, cambiar plan ni afirmar que los botones están en Lovable hasta confirmarlo después del despliegue. El directorio de GitHub Pages continúa como respaldo.

## Observaciones editoriales
- Los 45 registros comprenden 10 centros de atención públicos, 31 grupos de Jugadores Anónimos y 4 reuniones Jug-Anon en PBA.
- El centro de Olavarría tiene un conflicto de direcciones oficiales; conservar advertencia y confirmar antes de dirigir visitantes.
- Diferenciar reuniones de ayuda mutua de la atención profesional a distancia (UVA) del programa provincial.
- La actualización del directorio de GitHub debe conservar sincronizadas `docs/index.html` y `website/ayuda-pba.html`.
