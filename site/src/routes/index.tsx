import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowRight, LifeBuoy, ShieldCheck, RefreshCw, HeartHandshake, Lock, Clock } from "lucide-react";
import { HeroArt } from "@/components/HeroArt";
import { HelpBox } from "@/components/HelpBox";
import { DownloadBlock } from "@/components/DownloadBlock";
import { SectionTitle, StatusPill, meta } from "@/components/ui-bits";
import { siteConfig } from "@/config/site";
import { notes } from "@/content/education";

export const Route = createFileRoute("/")({
  head: () => {
    const h = meta(
      "VOLVÉ — Volvé a tomar el control frente a las apuestas online",
      "Software gratuito en desarrollo que te ayuda a poner barreras voluntarias entre vos y las apuestas online, con recursos de ayuda reales.",
      "/",
    );
    return {
      ...h,
      scripts: [{
        type: "application/ld+json",
        children: JSON.stringify({
          "@context": "https://schema.org",
          "@type": "SoftwareApplication",
          name: "VOLVÉ",
          applicationCategory: "UtilitiesApplication",
          operatingSystem: "Windows (en desarrollo), Android (planificado)",
          offers: { "@type": "Offer", price: "0", priceCurrency: "ARS" },
          inLanguage: "es-AR",
        }),
      }],
    };
  },
  component: Index,
});

const how = [
  { icon: ShieldCheck, title: "Protección voluntaria", text: "Vos decidís activarla. Suma una barrera entre el impulso y el sitio de apuestas." },
  { icon: RefreshCw, title: "Listas actualizadas", text: "Las listas de sitios se actualizan para acompañar la aparición de nuevas plataformas." },
  { icon: HeartHandshake, title: "Recursos de apoyo", text: "Acceso directo a líneas de ayuda gratuitas y a la autoexclusión oficial." },
];

function Index() {
  return (
    <>
      <section className="bg-hero">
        <div className="container-v grid items-center gap-12 py-16 md:grid-cols-[1.2fr_1fr] md:py-24">
          <div>
            <StatusPill>{siteConfig.devStatus} · {siteConfig.statusDate}</StatusPill>
            <h1 className="mt-6 text-5xl font-bold leading-[1.02] text-primary md:text-7xl">Volvé a tomar el control</h1>
            <p className="mt-6 max-w-xl text-xl leading-relaxed text-muted-foreground">
              Tecnología gratuita para poner barreras entre vos y las apuestas online.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Link to="/proyecto" className="inline-flex items-center gap-2 rounded-full bg-primary px-6 py-3.5 font-semibold text-primary-foreground shadow-soft transition hover:opacity-90">
                Conocé el proyecto <ArrowRight className="h-4 w-4" />
              </Link>
              <Link to="/centros-y-reuniones" className="inline-flex items-center gap-2 rounded-full bg-sage-soft px-6 py-3.5 font-semibold text-primary transition hover:bg-secondary">📍 Centros y reuniones</Link>
              <Link to="/ayuda" className="inline-flex items-center gap-2 rounded-full border-2 border-primary px-6 py-3 font-semibold text-primary transition hover:bg-secondary">
                <LifeBuoy className="h-4 w-4" /> Necesito ayuda
              </Link>
              <Link to="/colabora" className="inline-flex items-center gap-2 rounded-full bg-warm px-6 py-3.5 font-bold text-accent-foreground shadow-soft transition hover:opacity-90">
                <HeartHandshake className="h-5 w-5" aria-hidden="true" /> Colaborá con VOLVÉ
              </Link>
            </div>
            <p className="mt-6 inline-flex items-center gap-2 rounded-xl bg-card/70 px-4 py-2 text-sm text-muted-foreground">
              <Clock className="h-4 w-4" /> Descarga: <strong className="text-foreground">PRÓXIMAMENTE</strong> — todavía no hay instalador estable.
            </p>
          </div>
          <div className="mx-auto w-full max-w-sm"><HeroArt /></div>
        </div>
      </section>

      <section className="container-v py-20">
        <SectionTitle eyebrow="Cómo ayuda" title="Barreras digitales para ganar tiempo y tomar decisiones" intro="VOLVÉ está en desarrollo y pruebas. Queremos dificultar el acceso impulsivo a sitios de apuestas y mejorar la resistencia del bloqueo. Antes de lanzar, verificaremos su comportamiento en escenarios reales." />
        <div className="mt-10 grid gap-5 md:grid-cols-3">
          {how.map(({ icon: Icon, title, text }) => (
            <div key={title} className="rounded-3xl border border-border bg-card p-7 transition hover:shadow-soft">
              <span className="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-secondary"><Icon className="h-6 w-6 text-primary" /></span>
              <h3 className="mt-5 text-xl font-bold text-primary">{title}</h3>
              <p className="mt-2 leading-relaxed text-muted-foreground">{text}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="bg-sage-soft/60 py-20">
        <div className="container-v">
          <SectionTitle eyebrow="Ayuda ahora" title="Si lo necesitás hoy, no esperes al software" intro="Hablar con alguien es el paso más importante. Estas vías son gratuitas y existen ya." />
          <div className="mt-10"><HelpBox /></div>
          <Link to="/centros-y-reuniones" className="mt-6 inline-flex items-center rounded-full bg-primary px-6 py-3 font-semibold text-primary-foreground">📍 Encontrá ayuda cerca tuyo · 45 recursos en PBA</Link>
        </div>
      </section>

      <section className="container-v grid gap-10 py-20 md:grid-cols-2">
        <div>
          <SectionTitle eyebrow="Estado real" title="En desarrollo y pruebas" intro="A octubre de 2026 estamos probando la versión para Windows. Android viene después. Preferimos decirlo claro antes que publicar algo que no esté listo." />
          <p className="mt-6 flex items-center gap-2 text-sm text-muted-foreground"><Lock className="h-4 w-4" /> Sin cuentas, sin rastreo, sin venta de datos.</p>
        </div>
        <DownloadBlock />
      </section>

      <section className="container-v py-10">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <SectionTitle eyebrow="Educación" title="Notas para entender y prevenir" />
          <Link to="/educacion" className="inline-flex items-center gap-1 font-semibold text-primary hover:underline">Ver todas <ArrowRight className="h-4 w-4" /></Link>
        </div>
        <div className="mt-8 grid gap-5 md:grid-cols-3">
          {notes.slice(0, 3).map((n) => (
            <Link key={n.slug} to="/educacion" hash={n.slug} className="rounded-3xl bg-card p-6 border border-border transition hover:border-sage">
              <span className="text-xs font-semibold uppercase tracking-widest text-sage">{n.tag}</span>
              <h3 className="mt-3 text-lg font-bold text-primary">{n.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{n.summary}</p>
            </Link>
          ))}
        </div>
      </section>

      <section className="container-v pt-16">
        <div className="rounded-[2rem] bg-deep p-10 text-deep-foreground md:p-14">
          <h2 className="max-w-2xl text-3xl font-bold md:text-4xl">VOLVÉ es gratuito y queremos que siga siéndolo</h2>
          <p className="mt-4 max-w-2xl text-lg opacity-85">Tu ayuda suma: compartí el proyecto, colaborá con su difusión o conocé los futuros canales de aportes voluntarios. El software seguirá siendo gratuito.</p>
          <Link to="/colabora" className="mt-8 inline-flex items-center gap-2 rounded-full bg-warm px-6 py-3.5 font-semibold text-accent-foreground transition hover:opacity-90">
            Cómo colaborar <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      </section>
    </>
  );
}