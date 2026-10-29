import { Outlet, createRootRoute, HeadContent, Link } from "@tanstack/react-router";
import { SiteHeader } from "@/components/SiteHeader";
import { SiteFooter } from "@/components/SiteFooter";
export const Route = createRootRoute({
  head: () => ({
    meta: [
      { title: "VOLVÉ — Prevención de apuestas online" },
      { name: "description", content: "Proyecto argentino de tecnología gratuita en desarrollo y recursos de asistencia en la Provincia de Buenos Aires." },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
    ],
    links: [
      { rel: "icon", href: "/favicon.svg", type: "image/svg+xml" },
      { rel: "preconnect", href: "https://fonts.googleapis.com" },
      { rel: "stylesheet", href: "https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,500..800&family=Figtree:wght@400;500;600;700&display=swap" },
    ],
  }),
  component: () => <><HeadContent /><SiteHeader /><main id="contenido"><Outlet /></main><SiteFooter /></>,
  notFoundComponent: () => <section className="container-v py-24"><h1 className="text-4xl font-bold text-primary">Página no encontrada</h1><p className="my-5">El enlace ya no está disponible.</p><Link to="/" className="text-primary underline">Volver al inicio</Link></section>,
});
