import { useEffect, useState } from "react";
import { Eye } from "lucide-react";

// Servicio gratuito externo, separado del motor de protección de VOLVÉ.
// Sin cookies propias, cuentas ni almacenamiento de IP en nuestro sitio.
const SERVICE = "https://visitor-badge.one9x.com";
const PAGE_ID = "volve-web-onrender-2026";
const SESSION_KEY = "volve-web-visita-v2";
let pending: Promise<number> | null = null;

function hasBeenCounted(): boolean {
  try { return window.sessionStorage.getItem(SESSION_KEY) === "1"; }
  catch { return false; }
}

function markCounted() {
  try { window.sessionStorage.setItem(SESSION_KEY, "1"); }
  catch { /* Los navegadores pueden bloquear sessionStorage. */ }
}

async function getCount(): Promise<number> {
  if (pending) return pending;
  pending = (async () => {
    const alreadyCounted = hasBeenCounted();
    const baseUrl = `${SERVICE}/count?page_id=${PAGE_ID}`;
    const options: RequestInit = { cache: "no-store", referrerPolicy: "no-referrer" };
    // Primero comprobar CORS con una lectura sin incremento. Si falla,
    // usar un badge SVG, que no requiere CORS.
    const probe = await fetch(`${baseUrl}&read=true`, options);
    if (!probe.ok) throw new Error("Contador no disponible");
    if (alreadyCounted) {
      const result: unknown = await probe.json();
      const value = (result as { value?: unknown } | null)?.value;
      if (typeof value !== "number" || !Number.isFinite(value) || value < 0) throw new Error("Valor inválido");
      return value;
    }
    const response = await fetch(baseUrl, options);
    if (!response.ok) throw new Error("No se pudo registrar la visita");
    const result: unknown = await response.json();
    const value = (result as { value?: unknown } | null)?.value;
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0) throw new Error("Valor inválido");
    markCounted();
    return value;
  })().finally(() => { pending = null; });
  return pending;
}

export function VisitCounter() {
  const [count, setCount] = useState<number | null>(null);
  const [badgeFallback, setBadgeFallback] = useState(false);
  const [badgeError, setBadgeError] = useState(false);
  const [badgeReadOnly] = useState(() => hasBeenCounted());

  useEffect(() => {
    let mounted = true;
    getCount().then(
      (value) => { if (mounted) setCount(value); },
      () => { if (mounted) setBadgeFallback(true); },
    );
    return () => { mounted = false; };
  }, []);

  const badgeSrc = `${SERVICE}/badge?page_id=${PAGE_ID}&left_text=Visitas&left_color=%230E5558&right_color=%23E2B757&read=${badgeReadOnly ? "true" : "false"}&t=${Date.now()}`;
  return (
    <div className="rounded-2xl border border-deep-foreground/25 bg-deep-foreground/10 px-4 py-3" aria-label="Contador de visitas a la web de VOLVÉ">
      <p className="flex items-center gap-2 text-sm font-semibold"><Eye className="h-4 w-4" aria-hidden="true" /> Visitas a esta web</p>
      <div className="mt-1 min-h-9 text-2xl font-bold tabular-nums" role="status" aria-live="polite">
        {count !== null ? count.toLocaleString("es-AR") : badgeFallback && !badgeError
          ? <img className="mt-2 h-7 max-w-full" alt="Cantidad de visitas de VOLVÉ" src={badgeSrc} onLoad={() => { if (!badgeReadOnly) markCounted(); }} onError={() => setBadgeError(true)} referrerPolicy="no-referrer" />
          : badgeError ? "No disponible" : "Consultando…"}
      </div>
      <p className="mt-1 text-xs opacity-75">Desde el 30/10/2026 · Visitas contabilizadas, no personas únicas.</p>
    </div>
  );
}
