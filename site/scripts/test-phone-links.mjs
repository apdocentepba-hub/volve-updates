import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { runInNewContext } from "node:vm";

// Ejercita el helper TypeScript REAL (sin duplicar su algoritmo en el test).
const requireFromSite = createRequire(new URL("../package.json", import.meta.url));
const ts = requireFromSite("typescript");
const code = readFileSync("site/src/lib/phone-link.ts", "utf8");
const compiled = ts.transpileModule(code, {
  compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}
}).outputText;
const sandbox = {exports:{}};
runInNewContext(compiled, sandbox);
const {toDialHref} = sandbox.exports;
assert.equal(typeof toDialHref, "function");

const data = JSON.parse(readFileSync("site/src/data/ayuda-pba.json", "utf8"));
assert.equal(data.length,45);

const phoneRows = data.filter(r=>Boolean(r.telefono));
const callable = phoneRows.filter(r=>toDialHref(r.telefono)!==null);
const ambiguous = phoneRows.filter(r=>toDialHref(r.telefono)===null);
assert.equal(phoneRows.length,14);
assert.equal(callable.length,11);
assert.equal(ambiguous.length,3);
assert.deepEqual(ambiguous.map(x=>x.localidad),["Avellaneda","Olavarría","Pergamino"]);
assert.ok(callable.filter(x=>x.tipo==="familias").length===4);
assert.equal(toDialHref("+54 9 11 4085-8996"),"tel:+5491140858996");
assert.equal(toDialHref("0291 576-7117"),"tel:02915767117");
assert.equal(toDialHref("011 4483-6173"),"tel:01144836173");
assert.equal(toDialHref("011 4265-0080 / 4203-2161"),null);
assert.equal(toDialHref("2284-520151 (WhatsApp)"),null);
assert.equal(toDialHref("02477 41-4554 / 41-4555"),null);
for(const invalid of [undefined,"","  ","hola","1234","0800-444-4000;1234","tel:123456789","12345678#;","123456789<script>","+54 (x) 11 12345678","1".repeat(16)]){
  assert.equal(toDialHref(invalid),null, "Rejected ambiguous/untrusted phone: "+String(invalid));
}
for(const x of callable) {
 const href=toDialHref(x.telefono);
 assert.match(href,/^tel:\+?\d{8,15}$/);
 assert.ok(!href.includes("/"),"Never generate URL containing multiple alternatives");
}

const directory = readFileSync("site/src/routes/centros-y-reuniones.tsx","utf8");
assert.ok(directory.includes('import { toDialHref } from "@/lib/phone-link";'));
assert.ok(directory.includes('{r.telefono&&<PhoneContact number={r.telefono}/>}'));
assert.ok(directory.includes('const href=toDialHref(number);'));
assert.ok(directory.includes('{href&&<a href={href}'),"Must not render inert/invalid tel links");
assert.ok(directory.includes('aria-label={"Llamar al "+number}'),"Accessible link name");
assert.ok(directory.includes('min-h-10'),"Mobile finger target");
assert.ok(directory.includes("Días y horarios en conflicto entre fuentes oficiales"),"Prior safety warnings intact");
assert.ok(directory.includes("Ubicación a confirmar: no se muestran indicaciones"),"Prior safety warnings intact");
assert.doesNotMatch(code+directory,/navigator\.contacts|document\.cookie|sendBeacon|localStorage|sessionStorage|analytics\.track/);
console.log("VOLVE_MOBILE_PHONE_LINKS_OK", callable.length, "SAFE /", phoneRows.length, "ENTRIES WITH CONTACT DATA");
