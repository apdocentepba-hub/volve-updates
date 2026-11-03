import { createFileRoute } from "@tanstack/react-router";
import { ChevronDown } from "lucide-react";
import { PageHero, meta } from "@/components/ui-bits";
import { siteConfig, isLive } from "@/config/site";

const donationsEnabled = siteConfig.donations.some(c=>isLive(c.url)) || Boolean(siteConfig.bankTransfer.alias);
const faqs = [
  { q: "¿Es gratis?", a: "Sí. VOLVÉ es y va a seguir siendo gratuito. No hay precio, suscripción ni funciones pagas." },
  { q: "¿Ya está disponible?", a: "Todavía no. VOLVÉ continúa en desarrollo y pruebas, con Windows como primer objetivo y Android después. No hay instalador estable publicado: si ves un enlace de descarga fuera de este sitio, no es oficial." },
  { q: "¿Puedo aportar?", a: donationsEnabled ? "Sí. En la sección Colaborá figuran los enlaces y el alias público habilitados para aportes voluntarios. Antes de transferir o pagar, comprobá el destinatario y el importe en la plataforma. No hay ventajas ni funciones exclusivas por aportar. La ayuda de VOLVÉ siempre es gratuita." : "Los canales de aportes voluntarios están en preparación. No habrá funciones exclusivas por aportar y VOLVÉ seguirá siendo gratuito." },
  { q: "¿Sustituye un tratamiento?", a: "No. VOLVÉ no es terapia ni cura. Es una barrera que puede ayudar a reducir riesgos, como complemento de la atención profesional y de los programas públicos, como el 0800-444-4000 en la Provincia de Buenos Aires." },
  { q: "¿Cómo se usa?", a: "La idea es simple: lo instalás por decisión propia, activás la protección y el programa dificulta el acceso a sitios de apuestas conocidos, con listas que se actualizan. Publicaremos una guía paso a paso junto con la primera versión estable." },
  { q: "¿Qué pasa con mi privacidad?", a: "No pedimos cuentas ni datos personales, y no vendemos información. Este sitio no tiene formularios. Para mostrar el contador agregado de visitas, el navegador consulta el servicio externo Visitor Badge, que puede recibir la dirección IP y datos técnicos de conexión. Usamos sessionStorage en el navegador para evitar volver a contar una visita en la misma sesión. Las tipografías se cargan desde Google Fonts. No usamos estos servicios para elaborar perfiles personales." },
];

export const Route = createFileRoute("/preguntas")({
  head: () => ({
    ...meta("Preguntas frecuentes — VOLVÉ", "¿Es gratis? ¿Ya está disponible? ¿Reemplaza un tratamiento? Respuestas claras sobre VOLVÉ y la privacidad.", "/preguntas"),
    scripts: [{ type: "application/ld+json", children: JSON.stringify({ "@context": "https://schema.org", "@type": "FAQPage", mainEntity: faqs.map((f) => ({ "@type": "Question", name: f.q, acceptedAnswer: { "@type": "Answer", text: f.a } })) }) }],
  }),
  component: Preguntas,
});

function Preguntas() {
  return (
    <>
      <PageHero eyebrow="Preguntas frecuentes" title="Lo que más nos preguntan" intro="Respuestas directas, sin letra chica." />
      <section className="container-v max-w-3xl space-y-3 py-12">
        {faqs.map((f) => (
          <details key={f.q} className="group rounded-2xl border border-border bg-card p-6 open:shadow-soft">
            <summary className="flex cursor-pointer list-none items-center justify-between gap-4 text-lg font-semibold text-primary">
              {f.q}<ChevronDown className="h-5 w-5 shrink-0 transition group-open:rotate-180" />
            </summary>
            <p className="mt-4 leading-relaxed text-muted-foreground">{f.a}</p>
          </details>
        ))}
      </section>
    </>
  );
}