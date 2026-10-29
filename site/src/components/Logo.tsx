export function LogoMark({ className = "h-8 w-8" }: { className?: string }) {
  return (
    <svg viewBox="0 0 64 64" className={className} aria-hidden="true">
      <rect width="64" height="64" rx="18" fill="var(--deep)" />
      <path d="M18 22 L32 44 L46 22" fill="none" stroke="var(--sage)" strokeWidth="6" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M38 13 l5 -4" stroke="var(--warm)" strokeWidth="5" strokeLinecap="round" />
    </svg>
  );
}

export function Logo() {
  return (
    <span className="flex items-center gap-2.5">
      <LogoMark />
      <span className="font-display text-xl font-bold tracking-tight text-primary">VOLVÉ</span>
    </span>
  );
}