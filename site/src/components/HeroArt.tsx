/** Ilustración abstracta: un camino que vuelve, rodeado de capas protectoras. */
export function HeroArt() {
  return (
    <svg viewBox="0 0 400 400" className="h-full w-full" role="img" aria-label="Ilustración abstracta de un camino protegido">
      <circle cx="200" cy="200" r="180" fill="var(--sage-soft)" />
      <circle cx="200" cy="200" r="140" fill="none" stroke="var(--sage)" strokeWidth="2" strokeDasharray="4 10" />
      <circle cx="200" cy="200" r="100" fill="var(--background)" />
      <g className="animate-float">
        <path d="M120 250 C 160 160, 240 300, 280 170" fill="none" stroke="var(--primary)" strokeWidth="10" strokeLinecap="round" />
        <path d="M262 160 L284 166 L278 188" fill="none" stroke="var(--primary)" strokeWidth="10" strokeLinecap="round" strokeLinejoin="round" />
      </g>
      <circle cx="320" cy="90" r="22" fill="var(--warm)" opacity="0.85" />
      <circle cx="80" cy="310" r="12" fill="var(--warm)" opacity="0.6" />
    </svg>
  );
}