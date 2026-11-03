import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowRight, BookOpen, Download, ExternalLink, HeartHandshake, LifeBuoy, Phone, School, ShieldCheck } from "lucide-react";
import { PageHero, meta } from "@/components/ui-bits";
import { siteConfig } from "@/config/site";

const file = "/kit-escolar-volve.pdf";
const sources = [
  {
    title: "UNICEF Argentina · Zoom a las apuestas online",
    description: "Guía para familias y personas cuidadoras.",
    url: "https://www.unicef.org/argentina/informes/guia-apuestas-online",
  },
  {
    title: "UNICEF · Guía para docentes sobre educación financiera",
    description: "Orientaciones para trabajar en el aula.",
    url: "https://www.unicef.org/argentina/informes/guia-docentes-educacion-financiera",
  },
  {
    title: "Lotería PBA · Juego compulsivo",
    description: "Programa público y gratuito; teléfono 0800-444-4000.",
    url: siteConfig.help.source,
  },
  {
    title: "Argentina.gob.ar · Apuestas online y juego problemático",
    description: "Recomendaciones para familias y canales nacionales de orientación.",
    url: "https://www.argentina.gob.ar/capital-humano/familia/bienestar-emocional/somos-familia/apuestas-online-y-juego-problematico",
  },
];

const materials = [
  {
    n: "01",
    title: "Afiche escolar A4",
    description: "Una pieza breve para compartir el mensaje de prevención, el 0800 bonaerense y un QR a esta página.",
    symbol: School,
  },
  {
    n: "02",
    title: "Actividad de 15 minutos",
    description: "Secuencia orientativa para secundaria con un caso ficticio. No solicita experiencias ni datos personales.",
    symbol: BookOpen,
  },
  {
    n: "03",
    title: "Orientación para familias",
    description: "Señales para prestar atención, formas de conversar sin juzgar y recursos de acompañamiento.",
    symbol: HeartHandshake,
  },
];

export const Route = createFileRoute("/escuelas")({
  head: () => meta(
    "Kit educativo gratuito para escuelas y familias · VOLVÉ",
    "Descargá un afiche A4, una actividad de 15 minutos y una guía breve para familias sobre prevención de apuestas online, sin registro.",
    "/escuelas",
  ),
  component: Escuelas,
});

function Escuelas() {
  return (
    <>
      <PageHero
        eyebrow="Prevención · Material educativo gratuito"
        title="Hablemos de apuestas online antes de que sean un problema"
        intro="Un kit breve de VOLVÉ para abrir conversaciones cuidadosas con adolescentes, familias y equipos docentes. Se puede imprimir y compartir sin registrarse."
      />
      <section className="container-v pb-8 pt-12">
        <div className="grid items-center gap-7 rounded-[2rem] bg-deep p-7 text-deep-foreground md:grid-cols-[1.3fr_1fr] md:p-10">
          <div>
            <span className="inline-block rounded-full border border-deep-foreground/30 px-4 py-2 text-xs font-bold uppercase tracking-wider text-sage">
              3 páginas · Formato A4 · Noviembre 2026
            </span>
            <h2 className="mt-5 text-3xl font-bold md:text-4xl">Un recurso concreto para compartir</h2>
            <p className="mt-4 leading-relaxed text-deep-foreground/85">
              Incluye un afiche de prevención, una actividad breve para el aula y orientaciones para familias. No contiene publicidad de apuestas, formularios ni solicitudes de información personal.
            </p>
            <a href={file} download="VOLVE_Kit_Escolar_2026.pdf" type="application/pdf"
              className="mt-7 inline-flex min-h-12 items-center justify-center gap-2 rounded-full bg-warm px-6 py-3 font-bold text-accent-foreground transition hover:opacity-90">
              <Download aria-hidden="true" className="h-5 w-5"/> Descargar kit PDF para imprimir
            </a>
            <p className="mt-3 text-xs text-deep-foreground/75">PDF descargable, sin cuentas ni seguimiento de descargas de VOLVÉ.</p>
          </div>
          <div className="rounded-3xl border border-deep-foreground/20 bg-deep-foreground/10 p-6">
            <p className="text-sm font-semibold text-sage">La ayuda no depende del software</p>
            <a href={siteConfig.help.phoneHref} className="mt-4 block break-words text-3xl font-bold tracking-tight text-deep-foreground hover:underline">
              {siteConfig.help.phone}
            </a>
            <p className="mt-2 text-sm text-deep-foreground/85">Orientación pública y gratuita en Provincia de Buenos Aires para personas y familias.</p>
            <Link to="/centros-y-reuniones" className="mt-5 inline-flex items-center gap-2 text-sm font-bold text-sage underline underline-offset-4">
              Explorar centros y reuniones <ArrowRight aria-hidden="true" className="h-4 w-4"/>
            </Link>
          </div>
        </div>
      </section>
      <section className="container-v py-12" aria-labelledby="contenido-del-kit">
        <h2 id="contenido-del-kit" className="text-3xl font-bold text-primary">Qué incluye el kit</h2>
        <div className="mt-7 grid gap-5 md:grid-cols-3">
          {materials.map(({n,title,description,symbol:Icon}) => (
            <article key={n} className="rounded-3xl border border-border bg-card p-7">
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold text-sage">{n} / 03</span>
                <Icon aria-hidden="true" className="h-7 w-7 text-primary"/>
              </div>
              <h3 className="mt-6 text-xl font-bold text-primary">{title}</h3>
              <p className="mt-3 text-sm leading-relaxed text-muted-foreground">{description}</p>
            </article>
          ))}
        </div>
      </section>
      <section className="container-v pb-10" aria-labelledby="cuidados">
        <div className="rounded-3xl border border-border bg-sage-soft p-7 md:p-9">
          <h2 id="cuidados" className="flex items-center gap-2 text-2xl font-bold text-primary">
            <ShieldCheck aria-hidden="true" className="h-6 w-6"/> Cuidemos cómo abordamos el tema
          </h2>
          <p className="mt-4 max-w-3xl leading-relaxed text-foreground">
            En la escuela, usá situaciones ficticias: no pidas que estudiantes relaten públicamente experiencias de apuestas, deudas o situaciones familiares. Si alguien necesita apoyo, recurrí a los canales institucionales correspondientes y a profesionales de referencia.
          </p>
          <p className="mt-3 max-w-3xl text-sm text-muted-foreground">
            Este material no diagnostica ni reemplaza una intervención profesional. VOLVÉ es un proyecto independiente; no representa ni tiene convenio con UNICEF, Lotería PBA u otros organismos citados.
          </p>
        </div>
      </section>
      <section className="container-v py-12" aria-labelledby="fuentes-del-kit">
        <h2 id="fuentes-del-kit" className="text-2xl font-bold text-primary">Fuentes públicas para ampliar</h2>
        <ul className="mt-6 grid gap-4 md:grid-cols-2">
          {sources.map(s => <li key={s.url} className="rounded-2xl border border-border bg-card p-6">
            <a href={s.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-start gap-2 font-semibold text-primary underline underline-offset-4">
              {s.title}<ExternalLink aria-hidden="true" className="mt-1 h-4 w-4 shrink-0"/>
            </a>
            <p className="mt-2 text-sm text-muted-foreground">{s.description}</p>
          </li>)}
        </ul>
        <div className="mt-8 flex flex-wrap items-center gap-4 rounded-2xl bg-warm-soft px-5 py-4 text-sm text-accent-foreground">
          <LifeBuoy aria-hidden="true" className="h-5 w-5"/>
          <span>Si hay una situación de peligro inmediato, llamá al 911. Para orientación sobre niñas, niños y adolescentes, Línea 102; sobre consumos problemáticos, 141.</span>
        </div>
      </section>
      <section className="container-v pb-20">
        <Link to="/ayuda" className="inline-flex min-h-12 items-center gap-3 rounded-full bg-primary px-6 py-3 font-semibold text-primary-foreground">
          <Phone aria-hidden="true" className="h-5 w-5"/> Ver todas las opciones de ayuda
        </Link>
      </section>
    </>
  );
}
