import { useEffect, useState } from "react";
import { Eye } from "lucide-react";

// Contador independiente de la aplicación de bloqueo y sin datos de navegación.
// No guardar claves/tokens en el navegador: CounterAPI ofrece un endpoint público.
const COUNTER_URL = "https://counterapi.com/api/volve-web.onrender.com/view/visitas-web-oficial";
const SESSION_KEY = "volve-web-visita-v1";
let pending: Promise<number> | null = null;

async function getVisitCount(): Promise<number> {
  if (pending) return pending;
  pending = (async () => {
    let alreadyCounted = false;
    try {
      alreadyCounted = window.sessionStorage.getItem(SESSION_KEY) === "1";
    } catch {
      // Algunos navegadores deshabilitan el almacenamiento de sesión.
    }
    const response = await fetch(
      `${COUNTER_URL}?readOnly=${alreadyCounted ? "true" : "false"}`,
      { cache: "no-store", referrerPolicy: "no-referrer" },
    );
    if (!response.ok) throw new Error("No se pudo consultar el contador");
    const result: unknown = await response.json();
    const value = (result as { value?: unknown } | null)?.value;
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
      throw new Error("Respuesta inválida del contador");
    }
    if (!alreadyCounted) {
      try {
        window.sessionStorage.setItem(SESSION_KEY, "1");
      } catch {
        // El contador sigue funcionando, aunque no pueda deduplicar por pestaña.
      }
    }
    return value;
  })().finally(() => {
    pending = null;
  });
  return pending;
}

export function VisitCounter() {
  const [count, setCount] = useState<number | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  useEffect(() => {
    let mounted = true;
    getVisitCount().then(
      (value) => { if (mounted) setCount(value); },
      () => { if (mounted) setUnavailable(true); },
    );
    return () => { mounted = false; };
  }, []);

  return (
    <div className="rounded-2xl border border-deep-foreground/25 bg-deep-foreground/10 px-4 py-3" aria-label="Contador de visitas a la web de VOLVÉ">
      <p className="flex items-center gap-2 text-sm font-semibold"><Eye className="h-4 w-4" aria-hidden="true" /> Visitas a esta web</p>
      <p className="mt-1 text-2xl font-bold tabular-nums" role="status" aria-live="polite">
        {count !== null ? count.toLocaleString("es-AR") : unavailable ? "No disponible" : "Consultando…"}
      </p>
      <p className="mt-1 text-xs opacity-75">Desde el 30/10/2026 · Visitas contabilizadas, no personas únicas.</p>
    </div>
  );
}
