import assert from "node:assert/strict";
import {readFileSync} from "node:fs";

const src=readFileSync("site/src/routes/centros-y-reuniones.tsx","utf8");
const dir=JSON.parse(readFileSync("site/src/data/ayuda-pba.json","utf8"));
assert.equal(dir.length,45);
assert.equal(dir.filter(x=>x.tipo==="familias").length,4);
assert.equal(dir.filter(x=>x.tipo==="ja").length,31);

const getFunction=(name)=>{
 const begin=src.indexOf(" function "+name+"(");
 assert.ok(begin>=0,"Missing "+name);
 const body=src.slice(begin,src.indexOf("\n }",begin)+3);
 assert.ok(body.length>30,"Empty function "+name);
 return body;
};
const clear=getFunction("clearAll");
for(const field of ["Query","Kind","Zone","Day"]) assert.match(clear,new RegExp("set"+field+"\\(\"\"\\)"),"clear "+field);
assert.match(clear,/navigate\(\{to:"\/centros-y-reuniones",search:\{\},replace:true,hash:"buscar"\}\)/,"Clean URL and preserve list anchor");

const kind=getFunction("changeKind");
assert.match(kind,/setKind\(next\)/);
assert.match(kind,/search:next\?\{tipo:next as DirectorySearch\["tipo"\]\}:\{\}/);
assert.match(kind,/replace:true/);
assert.match(src,/validateSearch:\(search:Record<string,unknown>\):DirectorySearch=>/);
assert.match(src,/typeof candidate==="string"&&Object\.prototype\.hasOwnProperty\.call\(types,candidate\)/);
assert.match(src,/useEffect\(\(\)=>setKind\(safeKind\),\[safeKind\]\)/,"Re-sync via validated value");
assert.match(src,/const safeKind=typeof tipo==="string"&&Object\.prototype\.hasOwnProperty\.call\(types,tipo\)\?tipo:""/,"Invalid/unknown URLs never filter to 0");
assert.match(src,/onChange=\{e=>changeKind\(e\.target\.value\)\}/,"Dropdown persists selection");

assert.ok(src.includes("Limpiar todos los filtros"),"General reset displayed when filters active");
assert.ok(src.includes("(query||kind||zone||day)"),"Do not clutter default directory");
assert.ok(src.includes('onClick={clearAll}'),"Reset is wired");
assert.ok(src.includes("Mostrar los 45 recursos"),"No-results recovery CTA");
assert.ok(src.includes("No encontramos resultados con esos filtros."),"Zero-state message");
assert.ok(src.includes("Mostrar todos los recursos"),"Family-specific reset retained");
assert.match(src,/r\.verificacionPendiente!=="horarios"/,"Previous schedule protection retained");
assert.match(src,/r\.verificacionPendiente==="direccion"/,"Previous address protection retained");
assert.match(src,/toDialHref/,"Previous phone protection retained");
assert.doesNotMatch(src,/localStorage|sessionStorage|sendBeacon|document\.cookie|navigator\.contacts|gtag|trackEvent/i);
console.log("VOLVE_DIRECTORY_RESET_ALL_OK",dir.length);
