import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { ArrowRight, BookOpen, Copy, HeartHandshake, LifeBuoy, MapPin, Phone, Share2, ShieldCheck } from "lucide-react";
import { meta } from "@/components/ui-bits";
import { siteConfig } from "@/config/site";

export const Route = createFileRoute("/instagram")({
  head: () => meta(
    "VOLVÉ · Ayuda gratuita y prevención desde Instagram",
    "Recursos oficiales y gratuitos frente a las apuestas online: línea de asistencia de PBA, centros y reuniones, prevención y proyecto VOLVÉ.",
    "/instagram",
  ),
  component: Instagram,
});

const PAGE_URL = "https://volve-web.onrender.com/instagram";
const shareText = [
  "Si necesitás orientación frente a las apuestas online, hay ayuda gratuita en PBA:",
  "0800-444-4000 (programa oficial de asistencia).",
  "También podés consultar centros y reuniones sin registrarte:",
  PAGE_URL,
].join("\n");

function Instagram() {
  const [copyStatus, setCopyStatus] = useState("");
  async function copyHelpLink() {
    try {
      if (!navigator.clipboard?.writeText) throw new Error("Portapapeles no disponible");
      await navigator.clipboard.writeText(PAGE_URL);
      setCopyStatus("Enlace copiado. Compartilo solo si vos querés.");
    } catch {
      setCopyStatus("No se pudo copiar automáticamente. Seleccioná la dirección que aparece abajo.");
    }
  }
  return (
    <section className="bg-hero">
      <div className="container-v mx-auto max-w-2xl py-10 md:py-16">
        <div className="mb-7 text-center">
          <span className="inline-flex items-center gap-2 rounded-full bg-sage-soft px-4 py-2 text-xs font-bold uppercase tracking-wider text-primary">
            <HeartHandshake aria-hidden="true" className="h-4 w-4" /> VOLVÉ · Prevención
          </span>
          <h1 className="mt-5 text-4xl font-bold leading-tight text-primary md:text-5xl">
            Hay ayuda disponible. No hace falta esperar.
          </h1>
          <p className="mx-auto mt-4 max-w-xl text-base leading-relaxed text-muted-foreground md:text-lg">
            Si las apuestas te están afectando, o querés acompañar a alguien, acá encontrás recursos públicos gratuitos.
            También podés conocer nuestro proyecto de tecnología preventiva.
          </p>
        </div>

        <div className="space-y-4" aria-label="Enlaces útiles de VOLVÉ">
          <a
            href={siteConfig.help.phoneHref}
            className="flex min-h-28 items-center gap-4 rounded-3xl bg-deep px-6 py-5 text-deep-foreground shadow-soft transition hover:opacity-95 focus-visible:ring-4 focus-visible:ring-sage"
            aria-label={"Llamar al programa provincial de asistencia al juego compulsivo, " + siteConfig.help.phone}
          >
            <span className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-sage/20"><Phone aria-hidden="true" className="h-7 w-7 text-sage" /></span>
            <span className="min-w-0 flex-1">
              <strong className="block text-lg font-bold">Llamá gratis para pedir orientación</strong>
              <span className="mt-1 block font-display text-2xl font-bold">{siteConfig.help.phone}</span>
              <span className="mt-1 block text-xs opacity-80">Programa oficial de Provincia de Buenos Aires</span>
            </span>
            <ArrowRight aria-hidden="true" className="h-5 w-5 shrink-0" />
          </a>

          <Link to="/centros-y-reuniones" className="flex min-h-24 items-center gap-4 rounded-3xl border-2 border-primary bg-card px-6 py-5 text-primary shadow-soft transition hover:bg-secondary">
            <MapPin aria-hidden="true" className="h-7 w-7 shrink-0 text-primary" />
            <span className="flex-1">
              <strong className="block text-lg font-bold">Buscá centros y reuniones de ayuda</strong>
              <span className="mt-1 block text-sm text-muted-foreground">45 recursos de PBA, presenciales y virtuales. Confirmá horarios antes de asistir.</span>
            </span>
            <ArrowRight aria-hidden="true" className="h-5 w-5 shrink-0" />
          </Link>

          <Link to="/ayuda" className="flex min-h-24 items-center gap-4 rounded-3xl border border-border bg-card px-6 py-5 text-primary transition hover:border-sage">
            <LifeBuoy aria-hidden="true" className="h-6 w-6 shrink-0 text-primary" />
            <span className="flex-1">
              <strong className="block font-bold">Más formas de pedir ayuda</strong>
              <span className="mt-1 block text-sm text-muted-foreground">Orientación, autoexclusión oficial y alternativas para momentos difíciles.</span>
            </span>
            <ArrowRight aria-hidden="true" className="h-5 w-5 shrink-0" />
          </Link>
          <a
            href="https://jug-anon.org.ar/pages/grupos-autoayuda.html"
            target="_blank"
            rel="noopener noreferrer"
            className="flex min-h-24 items-center gap-4 rounded-3xl border border-border bg-card px-6 py-5 text-primary transition hover:border-sage"
          >
            <HeartHandshake aria-hidden="true" className="h-7 w-7 shrink-0 text-primary" />
            <span className="flex-1">
              <strong className="block font-bold">¿Acompañás a alguien? Hay ayuda para familiares</strong>
              <span className="mt-1 block text-sm text-muted-foreground">
                JUG-ANON reúne a familiares y amigos. Consultá sus grupos y confirmá los horarios en el sitio oficial.
              </span>
            </span>
            <ArrowRight aria-hidden="true" className="h-5 w-5 shrink-0" />
          </a>
        </div>

        <section className="mt-8 rounded-3xl border border-sage/60 bg-sage-soft p-6" aria-labelledby="compartir-ayuda">
          <h2 id="compartir-ayuda" className="text-xl font-bold text-primary">Compartí estos recursos de ayuda</h2>
          <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
            Puede servirle a alguien de tu entorno. Elegís vos con quién compartir; VOLVÉ no accede a tus contactos ni envía mensajes por tu cuenta.
          </p>
          <div className="mt-5 flex flex-col gap-3 sm:flex-row">
            <a
              href={`https://wa.me/?text=${encodeURIComponent(shareText)}`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex min-h-12 flex-1 items-center justify-center gap-2 rounded-full bg-primary px-5 py-3 font-semibold text-primary-foreground transition hover:opacity-90"
            >
              <Share2 aria-hidden="true" className="h-5 w-5" /> Compartir por WhatsApp
            </a>
            <button
              type="button"
              onClick={copyHelpLink}
              className="inline-flex min-h-12 flex-1 items-center justify-center gap-2 rounded-full border-2 border-primary bg-card px-5 py-3 font-semibold text-primary transition hover:bg-background"
            >
              <Copy aria-hidden="true" className="h-5 w-5" /> Copiar enlace
            </button>
          </div>
          <p className="mt-4 break-all text-xs font-medium text-muted-foreground">{PAGE_URL}</p>
          <p className="mt-2 min-h-5 text-sm text-primary" role="status" aria-live="polite">{copyStatus}</p>
        </section>

        <div className="mt-9 rounded-3xl border border-border bg-card p-6">
          <div className="flex items-start gap-3">
            <ShieldCheck aria-hidden="true" className="mt-1 h-6 w-6 shrink-0 text-primary" />
            <div>
              <h2 className="text-xl font-bold text-primary">¿Qué es VOLVÉ?</h2>
              <p className="mt-2 leading-relaxed text-muted-foreground">
                Desarrollamos un programa gratuito de bloqueo voluntario de sitios de apuestas.
                La versión de Windows sigue en pruebas y <strong className="text-foreground">no hay instalador público estable</strong>.
                No reemplaza la atención profesional.
              </p>
            </div>
          </div>
          <div className="mt-5 flex flex-col gap-3 sm:flex-row">
            <Link to="/proyecto" className="inline-flex flex-1 items-center justify-center gap-2 rounded-full bg-primary px-5 py-3 font-semibold text-primary-foreground">
              Conocé el proyecto <ArrowRight aria-hidden="true" className="h-4 w-4"/>
            </Link>
            <Link to="/educacion" className="inline-flex flex-1 items-center justify-center gap-2 rounded-full border border-primary px-5 py-3 font-semibold text-primary">
              <BookOpen aria-hidden="true" className="h-4 w-4" /> Educación y prevención
            </Link>
          </div>
        </div>

        <p className="mx-auto mt-6 max-w-xl text-center text-xs leading-relaxed text-muted-foreground">
          VOLVÉ es una iniciativa independiente. No organiza reuniones ni representa a los centros de ayuda.
          No requiere crear una cuenta, compartir datos personales ni pagar para consultar estos recursos.
          En una emergencia, acudí a una guardia o llamá al 911.
        </p>
      </div>
    </section>
  );
}
