import { Monitor, Smartphone, Download, Fingerprint } from "lucide-react";
import { siteConfig, isLive } from "@/config/site";
import { StatusPill } from "./ui-bits";

export function DownloadBlock() {
  const items = [
    { key: "windows" as const, icon: Monitor, name: "Windows", note: "Primer objetivo · en pruebas" },
    { key: "android" as const, icon: Smartphone, name: "Android", note: "Etapa posterior" },
  ];
  return (
    <div className="rounded-3xl border border-border bg-card p-6 md:p-8">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-xl font-bold text-primary">Descargas</h3>
        <StatusPill>Próximamente</StatusPill>
      </div>
      <p className="mt-2 text-sm text-muted-foreground">
        Todavía no hay un instalador estable. Cuando exista, vas a encontrar acá el enlace verificado junto con su huella SHA-256 para comprobar que el archivo es auténtico.
      </p>
      <div className="mt-6 grid gap-3 sm:grid-cols-2">
        {items.map(({ key, icon: Icon, name, note }) => {
          const d = siteConfig.download[key];
          const live = isLive(d.url);
          return (
            <div key={key} className="rounded-2xl bg-muted p-5">
              <div className="flex items-center gap-3">
                <Icon className="h-6 w-6 text-primary" />
                <div>
                  <p className="font-semibold">{name}</p>
                  <p className="text-xs text-muted-foreground">{note}</p>
                </div>
              </div>
              {live ? (
                <a href={d.url!} className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground">
                  <Download className="h-4 w-4" /> Descargar {d.version}
                </a>
              ) : (
                <button disabled aria-disabled="true" className="mt-4 inline-flex w-full cursor-not-allowed items-center justify-center gap-2 rounded-xl border border-dashed border-border px-4 py-2.5 text-sm font-medium text-muted-foreground">
                  <Download className="h-4 w-4" /> Próximamente
                </button>
              )}
              <p className="mt-3 flex items-center gap-1.5 break-all font-mono text-[11px] text-muted-foreground">
                <Fingerprint className="h-3.5 w-3.5 shrink-0" /> SHA-256: {d.sha256 ?? "se publicará con la versión estable"}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
}