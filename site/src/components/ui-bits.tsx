import type { ReactNode } from "react";

export function Eyebrow({ children }: { children: ReactNode }) {
  return <p className="mb-3 text-xs font-semibold uppercase tracking-[0.2em] text-sage">{children}</p>;
}

export function SectionTitle({ eyebrow, title, intro }: { eyebrow?: string; title: string; intro?: ReactNode }) {
  return (
    <div className="max-w-2xl">
      {eyebrow && <Eyebrow>{eyebrow}</Eyebrow>}
      <h2 className="text-3xl font-bold leading-tight text-primary md:text-4xl">{title}</h2>
      {intro && <p className="mt-4 text-lg leading-relaxed text-muted-foreground">{intro}</p>}
    </div>
  );
}

export function PageHero({ eyebrow, title, intro }: { eyebrow: string; title: string; intro: ReactNode }) {
  return (
    <section className="bg-hero">
      <div className="container-v py-16 md:py-24">
        <Eyebrow>{eyebrow}</Eyebrow>
        <h1 className="max-w-3xl text-4xl font-bold leading-[1.05] text-primary md:text-6xl">{title}</h1>
        <p className="mt-6 max-w-2xl text-lg leading-relaxed text-muted-foreground md:text-xl">{intro}</p>
      </div>
    </section>
  );
}

export function StatusPill({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-2 rounded-full bg-warm-soft px-3 py-1 text-xs font-semibold text-accent-foreground">
      <span className="h-2 w-2 animate-pulse rounded-full bg-warm" /> {children}
    </span>
  );
}

const SITE_ORIGIN = "https://volve-web.onrender.com";
const PREVIEW_IMAGE = SITE_ORIGIN + "/preview-volve.png";

export function meta(title: string, description: string, path: string) {
  const absoluteUrl = SITE_ORIGIN + (path.startsWith("/") ? path : "/" + path);
  return {
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
      { property: "og:type", content: "website" },
      { property: "og:locale", content: "es_AR" },
      { property: "og:site_name", content: "VOLVÉ · Prevención" },
      { property: "og:url", content: absoluteUrl },
      { property: "og:image", content: PREVIEW_IMAGE },
      { property: "og:image:secure_url", content: PREVIEW_IMAGE },
      { property: "og:image:type", content: "image/png" },
      { property: "og:image:width", content: "1080" },
      { property: "og:image:height", content: "1080" },
      { property: "og:image:alt", content: "VOLVÉ: programa gratuito de prevención de apuestas online, en desarrollo." },
      { name: "twitter:card", content: "summary_large_image" },
      { name: "twitter:image", content: PREVIEW_IMAGE },
    ],
    links: [{ rel: "canonical", href: absoluteUrl }],
  };
}
