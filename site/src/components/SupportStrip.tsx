import { Link } from "@tanstack/react-router";
import { HeartHandshake, ArrowRight } from "lucide-react";

/** Invitación voluntaria, separada del acceso a recursos de ayuda. */
export function SupportStrip() {
  return (
    <aside aria-label="Colaborar con el proyecto VOLVÉ" className="rounded-3xl border border-border bg-sage-soft p-6 md:flex md:items-center md:justify-between md:gap-8 md:p-8">
      <div>
        <h2 className="flex items-center gap-2 text-xl font-bold text-primary md:text-2xl"><HeartHandshake className="h-6 w-6" aria-hidden="true" /> Ayudanos a hacer crecer VOLVÉ</h2>
        <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted-foreground">Es un proyecto independiente y gratuito. Podés compartirlo, colaborar con tu experiencia o conocer cómo apoyar su desarrollo. Los aportes económicos todavía no están habilitados.</p>
      </div>
      <Link to="/colabora" className="mt-5 inline-flex shrink-0 items-center justify-center gap-2 rounded-full bg-warm px-6 py-3.5 font-bold text-accent-foreground transition hover:opacity-90 md:mt-0">
        Colaborá con VOLVÉ <ArrowRight className="h-4 w-4" aria-hidden="true" />
      </Link>
    </aside>
  );
}
