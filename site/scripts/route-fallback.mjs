import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

// WhatsApp/Meta preview crawlers may not execute React; build OG tags into initial HTML.
const root = "dist";
const origin = "https://volve-web.onrender.com";
const imageUrl = origin + "/preview-volve.png";
const originalIndex = readFileSync(join(root, "index.html"), "utf8");
const routes = {
  "": ["VOLVÉ — Prevención de apuestas online y recursos de ayuda",
       "Proyecto gratuito en desarrollo para sumar barreras frente a las apuestas online. Ayuda y 45 recursos en Provincia de Buenos Aires."],
  "instagram": ["VOLVÉ · Ayuda gratuita ante las apuestas online",
       "Llamá al 0800-444-4000 de Provincia de Buenos Aires, buscá centros y reuniones de ayuda y conocé VOLVÉ. Sin registro ni descargas."],
  "ayuda": ["Necesito ayuda · VOLVÉ Prevención",
       "Orientación gratuita frente a las apuestas online: línea provincial 0800-444-4000, autoexclusión oficial y recursos de acompañamiento."],
  "centros-y-reuniones": ["Centros y reuniones de ayuda en PBA · VOLVÉ",
       "Consultá centros públicos y reuniones de apoyo, presenciales y virtuales, en Provincia de Buenos Aires. Confirmá horarios con cada entidad."],
  "proyecto": ["Proyecto VOLVÉ · Tecnología gratuita en desarrollo",
       "Conocé VOLVÉ, iniciativa independiente de prevención de apuestas online. Software gratuito para Windows en pruebas, todavía sin descarga estable."],
  "educacion": ["Educación y prevención de apuestas · VOLVÉ",
       "Información educativa para comprender los riesgos de las apuestas online y conocer recursos gratuitos de orientación en Buenos Aires."],
  "colabora": ["Colaborá voluntariamente con VOLVÉ",
       "VOLVÉ seguirá siendo gratuito. Conocé cómo colaborar con la prevención y el desarrollo del proyecto, sin pagos obligatorios."],
  "preguntas": ["Preguntas frecuentes · VOLVÉ Prevención",
       "Preguntas sobre el software gratuito VOLVÉ, su desarrollo, la privacidad y los recursos de asistencia frente a las apuestas online."],
};

const escapeHtml = text => text.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

function headTags(path, title, description) {
  const url = escapeHtml(origin + (path ? "/" + path : "/"));
  const t = escapeHtml(title);
  const d = escapeHtml(description);
  return [
    '<meta property="og:type" content="website"/>',
    '<meta property="og:site_name" content="VOLVÉ · Prevención"/>',
    '<meta property="og:locale" content="es_AR"/>',
    '<meta property="og:title" content="' + t + '"/>',
    '<meta property="og:description" content="' + d + '"/>',
    '<meta property="og:url" content="' + url + '"/>',
    '<meta property="og:image" content="' + imageUrl + '"/>',
    '<meta property="og:image:secure_url" content="' + imageUrl + '"/>',
    '<meta property="og:image:type" content="image/png"/>',
    '<meta property="og:image:width" content="1080"/>',
    '<meta property="og:image:height" content="1080"/>',
    '<meta property="og:image:alt" content="VOLVÉ, proyecto independiente de prevención de apuestas online."/>',
    '<meta name="twitter:card" content="summary_large_image"/>',
    '<meta name="twitter:title" content="' + t + '"/>',
    '<meta name="twitter:description" content="' + d + '"/>',
    '<meta name="twitter:image" content="' + imageUrl + '"/>',
    '<link rel="canonical" href="' + url + '"/>',
  ].join("");
}

function htmlFor(path, [title, description]) {
  const updated = originalIndex
    .replace(/<title>[\s\S]*?<\/title>/i, "<title>" + escapeHtml(title) + "</title>")
    .replace(/<meta name="description" content="[^"]*"\/>/i,
       '<meta name="description" content="' + escapeHtml(description) + '"/>');
  if (!updated.includes("</head>")) throw new Error("HTML base sin head");
  return updated.replace("</head>", headTags(path, title, description) + "</head>");
}
for (const [path, copy] of Object.entries(routes)) {
  const folder = path ? join(root, path) : root;
  mkdirSync(folder, { recursive: true });
  writeFileSync(join(folder, "index.html"), htmlFor(path, copy));
}
console.log("Static deep-link HTML and social-preview metadata generated for", Object.keys(routes).length, "routes");
