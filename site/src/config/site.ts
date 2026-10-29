/**
 * Configuración editable de VOLVÉ.
 * Dejá en `null` todo enlace que todavía no esté verificado: el sitio
 * muestra "próximamente" y deshabilita el botón automáticamente.
 */
export type DonationChannel = { id: string; label: string; url: string | null; note?: string };

export const siteConfig = {
  name: "VOLVÉ",
  devStatus: "En desarrollo y pruebas",
  statusDate: "octubre 2026",
  instagramUrl: "https://www.instagram.com/volveprevencion/",
  download: {
    windows: { url: null as string | null, version: null as string | null, sha256: null as string | null },
    android: { url: null as string | null, version: null as string | null, sha256: null as string | null },
  },
  bankTransfer: {
    // Alias público facilitado por el responsable de VOLVÉ. No publicar el CBU completo.
    alias: null as string | null,
  },
  donations: [
    { id: "cafecito", label: "Invitá un Cafecito", url: "https://cafecito.app/volve" },
    { id: "mercadopago", label: "Mercado Pago · elegí el monto", url: "https://link.mercadopago.com.ar/volve" },
    { id: "transferencia", label: "Transferencia por alias", url: null },
  ] as DonationChannel[],
  transparency: {
    categories: ["Infraestructura", "Desarrollo", "Comunicación", "Remuneración del trabajo"],
    reports: [] as { period: string; url: string }[],
  },
  help: {
    phone: "0800-444-4000",
    phoneHref: "tel:08004444000",
    source: "https://loteria.gba.gob.ar/juego-compulsivo",
    /** Solo sitio oficial del regulador. Nunca enlazar a operadores de juego. */
    selfExclusion: "https://loteria.gba.gob.ar/juego-compulsivo",
  },
};

export const isLive = (url: string | null | undefined): url is string =>
  typeof url === "string" && /^https:\/\/.+/.test(url);