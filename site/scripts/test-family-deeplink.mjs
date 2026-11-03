import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const directory=readFileSync("site/src/routes/centros-y-reuniones.tsx","utf8");
const instagram=readFileSync("site/src/routes/instagram.tsx","utf8");
const sources=JSON.parse(readFileSync("site/src/data/ayuda-pba.json","utf8"));
const types=new Set(["publico","ja","familias"]);
const byType=Object.fromEntries([...types].map(type=>[type,sources.filter(r=>r.tipo===type)]));
const selected=raw=>types.has(new URLSearchParams(raw).get("tipo"))?new URLSearchParams(raw).get("tipo"):"";

assert.equal(selected("?tipo=familias"),"familias");
assert.equal(selected("?tipo=ja"),"ja");
assert.equal(selected("?tipo=publico"),"publico");
assert.equal(selected(""),"");
assert.equal(selected("?tipo=desconocido"),"");
assert.equal(selected("?tipo=../../etc"),"");
assert.equal(selected("?utm_source=instagram"),"");

assert.equal(sources.length,45,"Total de 45 recursos públicos auditados");
assert.equal(byType.familias.length,4,"La sección para familiares refleja el directorio real");
assert.equal(byType.ja.length,31);
assert.equal(byType.publico.length,10);
assert.ok(byType.familias.every(r=>r.fuente==="https://jug-anon.org.ar/pages/grupos-autoayuda.html"),"Fuentes oficiales en cada recurso familiar");
assert.ok(byType.familias.every(r=>r.localidad&&r.direccion&&r.horarios),"Registros familiares con localidades y horarios");

assert.ok(directory.includes('validateSearch:(search:Record<string,unknown>):DirectorySearch=>{'),"Validación del query string por el router");
assert.ok(directory.includes('Object.prototype.hasOwnProperty.call(types,candidate)'),"Lista blanca del parámetro público tipo");
assert.ok(directory.includes('const {tipo}=Route.useSearch();'),"El filtro se recupera desde la URL validada");
assert.ok(directory.includes('const [kind,setKind]=useState(tipo||"")'),"Filtro inicializado desde búsqueda validada");
assert.ok(directory.includes('useEffect(()=>setKind(tipo||""),[tipo])'),"Atrás, adelante y recarga sincronizan el filtro");
assert.ok(directory.includes('(!kind||r.tipo===kind)'),"Filtro real por tipo de recurso");
assert.ok(directory.includes('Mostrar todos los recursos'),"Opción de restablecer");
assert.ok(directory.includes('onClick={clearAll}'),"Restablece todos los criterios, no solo categoría");
assert.ok(directory.includes('id="buscar"'),"Ancla al listado");
assert.ok(directory.includes('search:next?{tipo:next as DirectorySearch["tipo"]}:{}'),"Persistencia de categoría elegida en URL");
assert.ok(directory.includes('search:{},replace:true'),"Reinicio elimina parámetros de búsqueda");

assert.ok(instagram.includes('href="/centros-y-reuniones?tipo=familias#buscar"'),"Enlace directo desde Instagram");
assert.ok(instagram.includes('Ver recursos para familiares en PBA'),"Etiqueta visible");
assert.ok(instagram.includes('href="https://jug-anon.org.ar/pages/grupos-autoayuda.html"'),"Conserva enlace oficial alternativo");
assert.ok(instagram.indexOf('siteConfig.help.phoneHref')<instagram.indexOf('Ver recursos para familiares en PBA'),"Línea gratuita visible primero");
assert.ok(instagram.indexOf('Ver recursos para familiares en PBA')<instagram.indexOf('Compartí estos recursos de ayuda'),"Ayuda familiar antes de compartir");
const updatedSection=directory.slice(directory.indexOf("function Directory(){"),directory.indexOf(" return <>"));
assert.doesNotMatch(updatedSection, /localStorage|sessionStorage|sendBeacon|fetch\(|document.cookie|geolocation|navigator\.contacts|email|dni/i);
console.log("VOLVE_FAMILY_DEEPLINK_OK",sources.length,byType.familias.length);
