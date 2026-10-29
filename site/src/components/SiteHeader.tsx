import { Link } from "@tanstack/react-router";
import { Menu, X, LifeBuoy } from "lucide-react";
import { useState } from "react";
import { Logo } from "./Logo";

const nav = [
  { to: "/proyecto", label: "El proyecto" },
  { to: "/educacion", label: "Educación" },
  { to: "/centros-y-reuniones", label: "Centros y reuniones" },
  { to: "/colabora", label: "Colaborá" },
  { to: "/preguntas", label: "Preguntas" },
] as const;

export function SiteHeader() {
  const [open, setOpen] = useState(false);
  return (
    <header className="sticky top-0 z-50 border-b border-border/70 bg-background/85 backdrop-blur-md">
      <a href="#contenido" className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-3 rounded bg-card px-3 py-2">
        Saltar al contenido
      </a>
      <div className="container-v flex h-16 items-center justify-between">
        <Link to="/" aria-label="VOLVÉ, inicio" onClick={() => setOpen(false)}>
          <Logo />
        </Link>
        <nav className="hidden items-center gap-1 md:flex" aria-label="Principal">
          {nav.map((n) => (
            <Link key={n.to} to={n.to} className="rounded-full px-4 py-2 text-sm font-medium text-muted-foreground transition hover:bg-muted hover:text-foreground" activeProps={{ className: "text-primary bg-secondary" }}>
              {n.label}
            </Link>
          ))}
          <Link to="/ayuda" className="ml-2 inline-flex items-center gap-2 rounded-full bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground transition hover:opacity-90">
            <LifeBuoy className="h-4 w-4" /> Necesito ayuda
          </Link>
        </nav>
        <button className="rounded-full p-2 md:hidden" aria-expanded={open} aria-controls="menu-movil" aria-label={open ? "Cerrar menú" : "Abrir menú"} onClick={() => setOpen(!open)}>
          {open ? <X /> : <Menu />}
        </button>
      </div>
      {open && (
        <nav id="menu-movil" className="border-t border-border bg-background md:hidden" aria-label="Menú móvil">
          <div className="container-v flex flex-col gap-1 py-4">
            {nav.map((n) => (
              <Link key={n.to} to={n.to} onClick={() => setOpen(false)} className="rounded-xl px-4 py-3 text-base font-medium hover:bg-muted">
                {n.label}
              </Link>
            ))}
            <Link to="/ayuda" onClick={() => setOpen(false)} className="mt-2 inline-flex items-center justify-center gap-2 rounded-xl bg-primary px-4 py-3 font-semibold text-primary-foreground">
              <LifeBuoy className="h-4 w-4" /> Necesito ayuda
            </Link>
          </div>
        </nav>
      )}
    </header>
  );
}