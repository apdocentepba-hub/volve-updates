import { Phone, ExternalLink, ShieldCheck } from "lucide-react";
import { siteConfig } from "@/config/site";

export function HelpBox() {
  const { help } = siteConfig;
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <a href={help.phoneHref} className="group rounded-3xl bg-deep p-7 text-deep-foreground shadow-soft transition hover:-translate-y-0.5">
        <Phone className="h-7 w-7 text-sage" />
        <p className="mt-5 text-sm opacity-80">Llamá gratis</p>
        <p className="font-display text-3xl font-bold md:text-4xl">{help.phone}</p>
        <p className="mt-3 text-sm leading-relaxed opacity-80">Programa oficial de prevención y asistencia al juego compulsivo de la Provincia de Buenos Aires. Gratuito y confidencial.</p>
      </a>
      <div className="flex flex-col gap-4">
        <a href={help.selfExclusion} target="_blank" rel="noopener noreferrer" className="flex items-start gap-4 rounded-3xl border border-border bg-card p-6 transition hover:border-sage">
          <ShieldCheck className="h-6 w-6 shrink-0 text-primary" />
          <span>
            <span className="flex items-center gap-1 font-semibold text-primary">Autoexclusión oficial — Provincia de Buenos Aires <ExternalLink className="h-3.5 w-3.5" /></span>
            <span className="mt-1 block text-sm text-muted-foreground">
              <strong className="text-foreground">Presencial:</strong> formulario y consentimiento para exclusión de salas de juego de PBA, en el sitio oficial de Lotería de la Provincia.
            </span>
          </span>
        </a>
        <div className="rounded-3xl border border-border bg-card p-6 text-sm text-muted-foreground">
          <strong className="text-foreground">Online:</strong> para autoexclusión online, consultá al regulador (0800-444-4000) o solicitá la opción en tu cuenta de juego, sin que VOLVÉ te envíe a un operador.
        </div>
        <p className="rounded-2xl bg-sage-soft px-5 py-3 text-sm font-semibold text-primary">VOLVÉ jamás enlaza a páginas de apuestas.</p>
      </div>
    </div>
  );
}