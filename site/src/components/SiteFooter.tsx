import { Link } from "@tanstack/react-router";
import { Instagram, Phone, HeartHandshake } from "lucide-react";
import { siteConfig, isLive } from "@/config/site";
import { Logo } from "./Logo";

export function SiteFooter() {
  const { help, instagramUrl } = siteConfig;
  return (
    <footer className="mt-24 bg-deep text-deep-foreground">
      <div className="container-v grid gap-10 py-14 md:grid-cols-3">
        <div className="space-y-4">
          <div className="rounded-xl bg-background/95 inline-block px-3 py-2"><Logo /></div>
          <p className="text-sm leading-relaxed opacity-80">
            VOLVÉ es un proyecto independiente de impacto social. No es una ONG formal ni tiene asociación con organismos estatales ni empresas de juego.
            No es terapia ni reemplaza la atención profesional.
          </p>
        </div>
        <div>
          <h2 className="mb-4 text-sm font-semibold uppercase tracking-widest opacity-70">Ayuda pública</h2>
          <ul className="space-y-3 text-sm">
            <li><a href={help.phoneHref} className="inline-flex items-center gap-2 underline-offset-4 hover:underline"><Phone className="h-4 w-4" /> {help.phone} (gratuito, PBA)</a></li>
            <li><a href={help.source} target="_blank" rel="noopener noreferrer" className="underline-offset-4 hover:underline">Programa de Juego Compulsivo — Lotería PBA</a></li>
            <li><a href={help.selfExclusion} target="_blank" rel="noopener noreferrer" className="underline-offset-4 hover:underline">Autoexclusión oficial — Provincia de Buenos Aires (salas presenciales)</a></li>
            <li className="opacity-75">VOLVÉ jamás enlaza a páginas de apuestas.</li>
          </ul>
        </div>
        <div>
          <h2 className="mb-4 text-sm font-semibold uppercase tracking-widest opacity-70">Proyecto</h2>
          <ul className="space-y-3 text-sm">
            <li><Link to="/proyecto" className="hover:underline">Qué es VOLVÉ</Link></li>
            <li><Link to="/educacion" className="hover:underline">Educación</Link></li>
            <li><Link to="/centros-y-reuniones" className="hover:underline">Centros y reuniones PBA</Link></li>
            <li><Link to="/colabora" className="inline-flex items-center gap-2 rounded-xl bg-warm px-4 py-2.5 font-bold text-accent-foreground hover:opacity-90"><HeartHandshake className="h-5 w-5" aria-hidden="true"/> Colaborá con VOLVÉ</Link></li>
            <li><Link to="/preguntas" className="hover:underline">Preguntas frecuentes</Link></li>
            <li className="inline-flex items-center gap-2">
              <Instagram className="h-4 w-4" />
              {isLive(instagramUrl) ? <a href={instagramUrl} target="_blank" rel="noopener noreferrer" className="hover:underline">Instagram</a> : <span className="opacity-75">Instagram del proyecto: próximamente</span>}
            </li>
          </ul>
        </div>
      </div>
      <div className="border-t border-deep-foreground/15">
        <p className="container-v py-5 text-xs opacity-60">© 2026 VOLVÉ · Este sitio no usa formularios ni recolecta datos personales.</p>
      </div>
    </footer>
  );
}