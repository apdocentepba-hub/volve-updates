import { createFileRoute } from "@tanstack/react-router";
import { Server, Code2, Megaphone, UserRound, FileText, HeartHandshake } from "lucide-react";
import { PageHero, SectionTitle, StatusPill, meta } from "@/components/ui-bits";
import { siteConfig, isLive } from "@/config/site";
import { Instagram, Share2, Users } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";

export const Route = createFileRoute("/colabora")({
  head: () => meta("Colaborá con VOLVÉ — Aportes voluntarios y transparencia", "VOLVÉ es gratuito y queremos que siga siéndolo. Conocé cómo se usarán los aportes voluntarios y nuestra política de transparencia.", "/colabora"),
  component: Colabora,
});

const uses = [
  { icon: Code2, t: "Desarrollo", d: "Nuevas funciones, pruebas y versión para Android." },
  { icon: Server, t: "Infraestructura", d: "Servidores, dominios, certificados y firma de software." },
  { icon: Megaphone, t: "Comunicación", d: "Materiales educativos y difusión responsable." },
  { icon: UserRound, t: "Remuneración del trabajo", d: "Pago transparente del tiempo del creador y colaboradores." },
];

function Colabora() {
  const channels = siteConfig.donations;
  const anyLive = channels.some((c) => isLive(c.url));
  const cafecitoUrl = channels.find((c) => c.id === "cafecito")?.url;
  const mercadoPagoUrl = channels.find((c) => c.id === "mercadopago")?.url;
  return (
    <>
      <PageHero eyebrow="Colaborá" title="VOLVÉ es gratuito y queremos que siga siéndolo" intro="Detrás hay horas de trabajo, pruebas y servidores. Si querés y podés, un aporte a voluntad nos ayuda a sostenerlo. Si no, usarlo y compartirlo también es colaborar." />
      <section className="container-v grid gap-6 py-12 lg:grid-cols-[1.3fr_1fr]">
        <div className="rounded-[2rem] bg-deep p-8 text-deep-foreground md:p-10">
          <HeartHandshake className="h-9 w-9 text-sage" />
          <h2 className="mt-5 text-3xl font-bold">Aportes a voluntad</h2>
          <p className="mt-4 text-lg leading-relaxed opacity-85">
            Los aportes son voluntarios y cada plataforma ofrece sus propias opciones de importe. El acceso al software nunca depende de pagar: no hay suscripción ni versión “premium”.
          </p>
          <div className="mt-8"><StatusPill>{anyLive ? "Canales habilitados" : "Canal de aportes en preparación"}</StatusPill></div>
          <div className="mt-5 grid gap-3 sm:grid-cols-3">
            {channels.map((c) =>
              isLive(c.url) ? (
                <a key={c.id} href={c.url} target="_blank" rel="noopener noreferrer" className="rounded-xl bg-warm px-4 py-3 text-center font-semibold text-accent-foreground">{c.label}</a>
              ) : (
                <button key={c.id} disabled aria-disabled="true" className="cursor-not-allowed rounded-xl border border-dashed border-deep-foreground/30 px-4 py-3 text-sm opacity-70">{c.label} · próximamente</button>
              ),
            )}
          </div>
          <p className="mt-5 text-xs opacity-80">Importante: en el enlace directo de Mercado Pago, la pantalla de pago muestra <strong>APDocentePBA</strong> como destinatario. Comprobá el nombre antes de confirmar cualquier aporte. No te pedimos claves ni datos bancarios.</p>
          <p className="mt-3 text-xs opacity-70">Solo vamos a habilitar canales oficiales verificados. Desconfiá de cualquier alias o cuenta que no figure en este sitio.</p>
        </div>
        <div className="grid gap-4">
          {uses.map(({ icon: I, t, d }) => (
            <div key={t} className="flex gap-4 rounded-2xl border border-border bg-card p-5"><I className="h-6 w-6 shrink-0 text-primary" /><div><h3 className="font-bold text-primary">{t}</h3><p className="text-sm text-muted-foreground">{d}</p></div></div>
          ))}
        </div>
      </section>
      {isLive(cafecitoUrl) && (
        <section className="container-v pb-8">
          <div className="grid gap-6 items-center rounded-3xl border border-border bg-card p-6 md:grid-cols-[auto_1fr] md:p-8">
            <div className="mx-auto rounded-2xl border border-border bg-white p-4">
              <QRCodeSVG value={cafecitoUrl} size={192} level="H" marginSize={4} title="QR oficial del perfil Cafecito de VOLVÉ" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-primary">Escaneá para apoyar a VOLVÉ</h2>
              <p className="mt-3 max-w-xl text-muted-foreground">Este QR abre exclusivamente nuestro perfil público de <strong>Cafecito</strong>. No es un QR de cobro directo de Mercado Pago. Ahí vas a ver los importes disponibles y los medios habilitados antes de pagar.</p>
              <a href={cafecitoUrl} target="_blank" rel="noopener noreferrer" className="mt-5 inline-flex items-center rounded-full bg-warm px-6 py-3 font-bold text-accent-foreground transition hover:opacity-90">Abrir Cafecito ↗</a>
              <p className="mt-3 break-all text-xs text-muted-foreground">{cafecitoUrl}</p>
            </div>
          </div>
        </section>
      )}
      {isLive(mercadoPagoUrl) && (
        <section className="container-v pb-8">
          <div className="grid gap-6 items-center rounded-3xl border border-border bg-card p-6 md:grid-cols-[auto_1fr] md:p-8">
            <div className="mx-auto rounded-2xl border border-border bg-white p-4">
              <QRCodeSVG value={mercadoPagoUrl} size={192} level="H" marginSize={4} title="QR que abre el enlace de Mercado Pago de VOLVÉ" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-primary">Aportá el monto que quieras con Mercado Pago</h2>
              <p className="mt-3 max-w-xl text-muted-foreground">Escaneá este QR o abrí el enlace y elegí cuánto aportar. Es un QR que dirige a <strong>Tu Link</strong> de Mercado Pago, no un QR de cobro presencial.</p>
              <p className="mt-3 max-w-xl rounded-xl bg-warm-soft p-3 text-sm text-accent-foreground"><strong>Antes de pagar:</strong> Mercado Pago mostrará <strong>APDocentePBA</strong> como nombre del receptor. Confirmá que sea ese destinatario y revisá el importe.</p>
              <a href={mercadoPagoUrl} target="_blank" rel="noopener noreferrer" className="mt-5 inline-flex items-center rounded-full bg-warm px-6 py-3 font-bold text-accent-foreground transition hover:opacity-90">Abrir Mercado Pago ↗</a>
              <p className="mt-3 break-all text-xs text-muted-foreground">{mercadoPagoUrl}</p>
            </div>
          </div>
        </section>
      )}
      <section className="container-v py-12">
        <SectionTitle eyebrow="Colaborar sin dinero" title="Podés ayudar desde ahora" intro="Además de los aportes voluntarios, podés ayudar sin gastar dinero. Estas opciones siempre estarán disponibles." />
        <div className="mt-7 grid gap-4 md:grid-cols-3">
          <a href={"https://api.whatsapp.com/send?text="+encodeURIComponent("Conocé VOLVÉ: un proyecto argentino que desarrolla tecnología gratuita para prevenir apuestas online. https://volve-web.onrender.com/")} target="_blank" rel="noopener noreferrer" className="group rounded-3xl border border-border bg-card p-7 transition hover:border-sage hover:shadow-soft">
            <Share2 className="h-7 w-7 text-primary" aria-hidden="true"/>
            <h3 className="mt-4 text-xl font-bold text-primary">Compartí el proyecto</h3>
            <p className="mt-2 text-sm leading-relaxed text-muted-foreground">Mandá la web por WhatsApp a alguien que quiera conocerla, sin enviar mensajes automáticamente.</p>
            <span className="mt-5 inline-block font-semibold text-primary underline">Compartir por WhatsApp ↗</span>
          </a>
          <a href={siteConfig.instagramUrl} target="_blank" rel="noopener noreferrer" className="group rounded-3xl border border-border bg-card p-7 transition hover:border-sage hover:shadow-soft">
            <Instagram className="h-7 w-7 text-primary" aria-hidden="true"/>
            <h3 className="mt-4 text-xl font-bold text-primary">Ayudanos a difundir</h3>
            <p className="mt-2 text-sm leading-relaxed text-muted-foreground">Seguí @volveprevencion y compartí contenidos de prevención que puedan servir.</p>
            <span className="mt-5 inline-block font-semibold text-primary underline">Instagram de VOLVÉ ↗</span>
          </a>
          <a href={siteConfig.instagramUrl} target="_blank" rel="noopener noreferrer" className="group rounded-3xl border border-border bg-card p-7 transition hover:border-sage hover:shadow-soft">
            <Users className="h-7 w-7 text-primary" aria-hidden="true"/>
            <h3 className="mt-4 text-xl font-bold text-primary">Ofrecé tu colaboración</h3>
            <p className="mt-2 text-sm leading-relaxed text-muted-foreground">¿Querés aportar conocimiento técnico, diseño o difusión? Podés escribirnos por Instagram.</p>
            <span className="mt-5 inline-block font-semibold text-primary underline">Contactar al proyecto ↗</span>
          </a>
        </div>
      </section>
      <section className="container-v py-12" id="transparencia">
        <SectionTitle eyebrow="Transparencia" title="Cuentas claras, siempre" intro="Nos comprometemos a publicar reportes periódicos con ingresos y egresos agrupados por categoría." />
        <div className="mt-8 rounded-3xl border border-border bg-card p-6 md:p-8">
          <div className="grid gap-3 sm:grid-cols-4">
            {siteConfig.transparency.categories.map((c) => (
              <div key={c} className="rounded-2xl bg-muted p-4"><p className="text-xs uppercase tracking-widest text-muted-foreground">{c}</p><p className="mt-2 font-display text-2xl font-bold text-primary">—</p></div>
            ))}
          </div>
          {siteConfig.transparency.reports.length === 0 ? (
            <p className="mt-6 flex items-center gap-2 text-muted-foreground"><FileText className="h-5 w-5" /> Primer informe pendiente: Cafecito y Mercado Pago directo están habilitados, pero no publicaremos cifras hasta verificar los movimientos.</p>
          ) : (
            <ul className="mt-6 space-y-2">{siteConfig.transparency.reports.map((r) => <li key={r.url}><a href={r.url} className="text-primary underline">{r.period}</a></li>)}</ul>
          )}
        </div>
      </section>
    </>
  );
}