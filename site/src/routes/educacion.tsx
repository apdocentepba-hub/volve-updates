import { createFileRoute } from "@tanstack/react-router";
import { Sparkles } from "lucide-react";
import { PageHero, SectionTitle, meta } from "@/components/ui-bits";
import { notes, upcoming } from "@/content/education";
import { SupportStrip } from "@/components/SupportStrip";

export const Route = createFileRoute("/educacion")({
  head: () => meta("Educación sobre apuestas online y prevención — VOLVÉ", "Notas breves y claras para entender por qué cuesta frenar, qué señales mirar y cómo cuidarse frente a las apuestas online.", "/educacion"),
  component: Educacion,
});

function Educacion() {
  const full = notes.filter((n) => n.body);
  return (
    <>
      <PageHero eyebrow="Educación" title="Entender ayuda a cuidarse" intro="Mini notas sobrias, pensadas para compartir con amistades, familias y escuelas." />
      <section className="container-v py-12">
        <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {notes.map((n, i) => (
            <a key={n.slug} href={n.body ? `#${n.slug}` : undefined} className={`flex flex-col rounded-3xl p-7 border border-border ${i % 3 === 0 ? "bg-secondary" : i % 3 === 1 ? "bg-card" : "bg-warm-soft"}`}>
              <span className="text-xs font-semibold uppercase tracking-widest text-sage">{n.tag}</span>
              <h2 className="mt-3 text-xl font-bold text-primary">{n.title}</h2>
              <p className="mt-3 flex-1 text-sm leading-relaxed text-muted-foreground">{n.summary}</p>
              {n.body && <span className="mt-4 text-sm font-semibold text-primary">Leer nota completa →</span>}
            </a>
          ))}
        </div>
      </section>
      {full.map((n) => (
        <article key={n.slug} id={n.slug} className="container-v scroll-mt-24 py-12">
          <div className="rounded-[2rem] border border-border bg-card p-8 md:p-12">
            <span className="text-xs font-semibold uppercase tracking-widest text-sage">{n.tag} · Nota completa</span>
            <h2 className="mt-3 text-3xl font-bold text-primary md:text-4xl">{n.title}</h2>
            <p className="mt-4 max-w-2xl text-lg text-muted-foreground">{n.summary}</p>
            <div className="mt-8 grid gap-6 md:grid-cols-2">
              {n.body!.map((b, i) => (
                <div key={b.heading} className="flex gap-4">
                  <span className="font-display text-3xl font-bold text-sage">{String(i + 1).padStart(2, "0")}</span>
                  <div><h3 className="font-bold text-primary">{b.heading}</h3><p className="mt-1 leading-relaxed text-muted-foreground">{b.text}</p></div>
                </div>
              ))}
            </div>
          </div>
        </article>
      ))}
      <section className="container-v py-12">
        <SectionTitle eyebrow="Novedades" title="Próximos contenidos" />
        <ul className="mt-6 grid gap-3 md:grid-cols-3">
          {upcoming.map((u) => <li key={u} className="flex items-start gap-3 rounded-2xl border border-dashed border-border p-5 text-muted-foreground"><Sparkles className="h-5 w-5 shrink-0 text-warm" />{u}</li>)}
        </ul>
      </section>
      <div className="container-v pt-8"><SupportStrip /></div>
    </>
  );
}