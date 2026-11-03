import assert from "node:assert/strict";
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const root = "site/dist";
const base = "https://volve-web.onrender.com";
const image = base + "/preview-volve.png";
const cases = [
  ["", "VOLVÉ — Prevención de apuestas online y recursos de ayuda"],
  ["instagram", "VOLVÉ · Ayuda gratuita ante las apuestas online"],
  ["ayuda", "Necesito ayuda · VOLVÉ Prevención"],
  ["centros-y-reuniones", "Centros y reuniones de ayuda en PBA · VOLVÉ"],
  ["proyecto", "Proyecto VOLVÉ · Tecnología gratuita en desarrollo"],
  ["escuelas", "Kit educativo para escuelas y familias · VOLVÉ"],
  ["educacion", "Educación y prevención de apuestas · VOLVÉ"],
  ["colabora", "Colaborá voluntariamente con VOLVÉ"],
  ["preguntas", "Preguntas frecuentes · VOLVÉ Prevención"],
];

for (const [route, title] of cases) {
  const f = join(root, route, "index.html");
  const html = readFileSync(f, "utf8");
  const canonical = base + (route ? "/" + route : "/");
  assert.ok(html.includes("<title>" + title + "</title>"), f + " title");
  for (const [property, value] of [
    ["og:title", title], ["og:url", canonical], ["og:image", image],
    ["og:image:secure_url", image], ["og:type", "website"],
    ["og:locale", "es_AR"], ["og:image:width", "1080"], ["og:image:height", "1080"],
  ]) {
    assert.ok(html.includes('property="' + property + '" content="' + value + '"'), f + " missing " + property);
  }
  assert.ok(html.includes('rel="canonical" href="' + canonical + '"'), f + " canonical");
  assert.ok(html.includes('name="twitter:image" content="' + image + '"'), f + " twitter");
  assert.equal((html.match(/property="og:image"/g) || []).length, 1, f + " duplicate og:image");
  assert.ok(html.indexOf('property="og:image"') < html.indexOf("</head>"), f + " not in static head");
  assert.ok(html.includes('name="description"'), f + " static description");
  assert.ok(html.includes('<div id="root"></div>'), f + " missing SPA root");
  assert.ok(html.indexOf('property="og:title"') < html.indexOf('<div id="root">'), f + " depends on JS");
  assert.doesNotMatch(html, /<script[^>]*src=["']https?:\/\/(?!volve-web\.onrender\.com)/, f + " external JS injection");
  console.log("STATIC_PREVIEW_OK", route || "/");
}
const bytes = readFileSync(join(root, "preview-volve.png"));
assert.ok(bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])), "PNG magic");
assert.equal(bytes.readUInt32BE(16),1080,"PNG width");
assert.equal(bytes.readUInt32BE(20),1080,"PNG height");
assert.ok(bytes.length>10000 && bytes.length < 600000, "PNG reasonable for link previews");
const metaHelper = readFileSync("site/src/components/ui-bits.tsx","utf8");
assert.match(metaHelper,/SITE_ORIGIN \+ \(path\.startsWith/);
assert.match(metaHelper,/og:image/);
assert.match(metaHelper,/canonical/);
const landing = readFileSync("site/src/routes/instagram.tsx","utf8");
assert.ok(landing.includes("https://jug-anon.org.ar/pages/grupos-autoayuda.html"));
assert.ok(landing.includes("familiares"));
assert.ok(landing.includes("confirmá los horarios"));
assert.ok(landing.indexOf("0800-444-4000") >= 0 || landing.includes("siteConfig.help.phoneHref"));
assert.ok(landing.includes('target="_blank"') && landing.includes('rel="noopener noreferrer"'));
console.log("PREVIEW_IMAGE_AND_FAMILIES_OK",bytes.length);
