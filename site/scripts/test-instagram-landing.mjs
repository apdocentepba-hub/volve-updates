import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const route = readFileSync("site/src/routes/instagram.tsx", "utf8");
const fallback = readFileSync("site/scripts/route-fallback.mjs", "utf8");
const config = readFileSync("site/src/config/site.ts", "utf8");

assert.match(route, /createFileRoute\("\/instagram"\)/);
assert.match(fallback, /"instagram"/);
assert.match(route, /siteConfig\.help\.phoneHref/);
assert.match(config, /phoneHref:\s*"tel:08004444000"/);
for (const path of ["/centros-y-reuniones","/ayuda","/proyecto","/educacion"]) {
  assert.ok(route.includes(path), "Falta enlace de ayuda: "+path);
}
const helpIndex=route.indexOf("Llamá gratis para pedir orientación");
const centersIndex=route.indexOf("Buscá centros y reuniones de ayuda");
const projectIndex=route.indexOf("¿Qué es VOLVÉ?");
assert.ok(helpIndex>0 && centersIndex>helpIndex && projectIndex>centersIndex,"Ayuda y centros deben aparecer antes que presentación comercial");
assert.match(route, /no hay instalador público estable/i);
assert.match(route, /No reemplaza la atención profesional/);
assert.match(route, /No requiere crear una cuenta/);
assert.match(route, /VOLVÉ es una iniciativa independiente/);

const shareIndex=route.indexOf("Compartí estos recursos de ayuda");
assert.ok(shareIndex>centersIndex && shareIndex<projectIndex,"La opción voluntaria de compartir no debe desplazar los recursos de ayuda");
assert.match(route, /Compartir por WhatsApp/);
assert.match(route, /https:\/\/wa\.me\/\?text=/);
assert.match(route, /encodeURIComponent\(shareText\)/);
assert.match(route, /target="_blank"/);
assert.match(route, /rel="noopener noreferrer"/);
assert.match(route, /navigator\.clipboard\.writeText\(PAGE_URL\)/);
assert.match(route, /onClick=\{copyHelpLink\}/);
assert.match(route, /no accede a tus contactos ni envía mensajes por tu cuenta/);
assert.match(route, /role="status" aria-live="polite"/);
assert.match(route, /Enlace copiado. Compartilo solo si vos querés./);

assert.doesNotMatch(route,/fetch\(|sendBeacon|localStorage|sessionStorage|document\.cookie|window\.location|utm_source|formsubmit|mercadopago|cafecito|casino|bet\.ar/i);
console.log("VOLVE_INSTAGRAM_LANDING_STATIC_OK",23);
