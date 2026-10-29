import { createFileRoute } from "@tanstack/react-router";
import { Target, Check, AlertTriangle, HandHeart, Lock, Stethoscope } from "lucide-react";
import { PageHero, SectionTitle, meta } from "@/components/ui-bits";
import { DownloadBlock } from "@/components/DownloadBlock";

export const Route = createFileRoute("/proyecto")({
  head: () => meta("Qué es VOLVÉ — Misión, alcance y estado del desarrollo", "Conocé la misión de VOLVÉ, por qué una barrera digital voluntaria ayuda, sus límites y el estado real del desarrollo.", "/proyecto"),
  component: Proyecto,
});

const sirve = [
  "Suma fricción en el momento del impulso, cuando más cuesta frenar.",
  "Es una decisión tuya: intervención consentida, nunca impuesta a escondidas.",
  "Complementa la autoexclusión oficial y el acompañamiento profesional.",
  "Reduce el riesgo; no busca castigar ni vigilar.",
];
const limites = [
  "La protección digital está en desarrollo y todavía requiere pruebas en situaciones reales.",
  "Es una herramienta de apoyo, no una garantía absoluta ni un sustituto de la autoexclusión y la atención profesional.",
  "Estamos trabajando para reforzar la continuidad del bloqueo ante cambios de conectividad y configuraciones del equipo.",
  "Las listas y mecanismos de protección necesitan mantenimiento y validación continua.",
];
const pillars = [
  { icon: HandHeart, t: "Consentimiento", d: "Lo activa la propia persona, o alguien de confianza con su acuerdo." },
  { icon: Lock, t: "Privacidad", d: "No pedimos cuentas, no registramos tu navegación, no vendemos datos." },
  { icon: Stethoscope, t: "Vías legítimas", d: "Siempre orientamos hacia programas públicos y profesionales." },
];

function Proyecto() {
  return (
    <>
      <PageHero eyebrow="El proyecto" title="Tecnología protectora, hecha con cuidado" intro="VOLVÉ es un software gratuito, desarrollado en Argentina, para ayudar a reducir el acceso impulsivo a apuestas online mediante barreras digitales voluntarias y recursos de ayuda." />
      <section className="container-v py-16">
        <div className="flex items-start gap-4 rounded-3xl bg-secondary p-8">
          <Target className="h-8 w-8 shrink-0 text-primary" />
          <div>
            <h2 className="text-2xl font-bold text-primary">Nuestra misión</h2>
            <p className="mt-2 text-lg leading-relaxed text-secondary-foreground">Que cualquier persona que quiera alejarse de las apuestas online tenga a mano, sin costo, una herramienta simple que le dé tiempo para elegir distinto, y un camino claro hacia ayuda real.</p>
          </div>
        </div>
      </section>
      <section className="container-v grid gap-6 md:grid-cols-2">
        <div className="rounded-3xl border border-border bg-card p-8">
          <h2 className="text-2xl font-bold text-primary">Por qué sirve</h2>
          <ul className="mt-5 space-y-3">{sirve.map((s) => <li key={s} className="flex gap-3"><Check className="mt-0.5 h-5 w-5 shrink-0 text-sage" />{s}</li>)}</ul>
        </div>
        <div className="rounded-3xl border border-border bg-warm-soft p-8">
          <h2 className="text-2xl font-bold text-accent-foreground">Protección responsable</h2>
          <ul className="mt-5 space-y-3">{limites.map((s) => <li key={s} className="flex gap-3"><AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-warm" />{s}</li>)}</ul>
        </div>
      </section>
      <section className="container-v py-16">
        <SectionTitle eyebrow="Principios" title="Cómo lo pensamos" />
        <div className="mt-8 grid gap-5 md:grid-cols-3">
          {pillars.map(({ icon: I, t, d }) => (
            <div key={t} className="rounded-3xl bg-card p-7 border border-border"><I className="h-7 w-7 text-primary" /><h3 className="mt-4 text-lg font-bold text-primary">{t}</h3><p className="mt-2 text-muted-foreground">{d}</p></div>
          ))}
        </div>
      </section>
      <section className="container-v grid gap-10 md:grid-cols-2" id="estado">
        <div>
          <SectionTitle eyebrow="Estado del desarrollo" title="En desarrollo y pruebas (octubre 2026)" />
          <ol className="mt-6 space-y-4 border-l-2 border-sage pl-6">
            <li><p className="font-semibold">Windows — en pruebas</p><p className="text-sm text-muted-foreground">Primer objetivo. Sin instalador estable publicado todavía.</p></li>
            <li><p className="font-semibold">Android — planificado</p><p className="text-sm text-muted-foreground">Se trabajará después de estabilizar Windows.</p></li>
            <li><p className="font-semibold">Versión pública verificada — pendiente</p><p className="text-sm text-muted-foreground">Se publicará con enlace oficial y huella SHA-256.</p></li>
          </ol>
        </div>
        <DownloadBlock />
      </section>
    </>
  );
}