import { createFileRoute } from "@tanstack/react-router";
import { Wind, MessageCircle, Wallet, Smartphone, Heart } from "lucide-react";
import { PageHero, SectionTitle, meta } from "@/components/ui-bits";
import { HelpBox } from "@/components/HelpBox";

export const Route = createFileRoute("/ayuda")({
  head: () => meta("Necesito ayuda — VOLVÉ", "Llamá gratis al 0800-444-4000, programa oficial de la Provincia de Buenos Aires. Autoexclusión y consejos breves para el momento difícil.", "/ayuda"),
  component: Ayuda,
});

const tips = [
  { icon: Wind, t: "Date diez minutos", d: "Las ganas fuertes suelen bajar si esperás. Salí del lugar, tomá agua, respirá lento." },
  { icon: MessageCircle, t: "Contáselo a alguien", d: "Una persona de confianza o la línea gratuita. Decirlo en voz alta alivia." },
  { icon: Wallet, t: "Alejá la plata", d: "Pedí que alguien te guarde la tarjeta o poné límites en tu billetera virtual por un tiempo." },
  { icon: Smartphone, t: "Sumá barreras", d: "Autoexclusión, borrar apps y bloquear sitios: cada traba te da tiempo." },
  { icon: Heart, t: "Tratate con amabilidad", d: "Esto no te define. Si tropezaste, podés volver a empezar hoy." },
];

function Ayuda() {
  return (
    <>
      <PageHero eyebrow="Ayuda" title="No tenés que atravesarlo solo ni sola" intro="Si sentís que las apuestas te están ganando terreno, hay personas preparadas para escucharte, gratis y sin juzgar." />
      <section className="container-v py-12"><HelpBox /></section>
      <section className="container-v py-12">
        <SectionTitle eyebrow="Para el momento difícil" title="Algunas ideas breves" intro="No son un diagnóstico ni un tratamiento: son gestos simples que a muchas personas les sirven." />
        <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {tips.map(({ icon: I, t, d }) => (
            <div key={t} className="rounded-3xl border border-border bg-card p-6"><I className="h-6 w-6 text-sage" /><h3 className="mt-3 font-bold text-primary">{t}</h3><p className="mt-1 text-sm text-muted-foreground">{d}</p></div>
          ))}
        </div>
        <p className="mt-10 rounded-2xl bg-warm-soft p-5 text-sm text-accent-foreground">Si estás en peligro o pensás en hacerte daño, llamá al 135 (CABA y GBA, Centro de Asistencia al Suicida) o acercate a una guardia. Ante una emergencia, 107 o 911.</p>
      </section>
    </>
  );
}