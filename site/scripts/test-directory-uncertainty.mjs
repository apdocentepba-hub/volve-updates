import assert from "node:assert/strict";
import {readFileSync} from "node:fs";

const data=JSON.parse(readFileSync("site/src/data/ayuda-pba.json","utf8"));
const src=readFileSync("site/src/routes/centros-y-reuniones.tsx","utf8");
const types=new Set(["publico","ja","familias"]);
const rowsWithWarnings=data.filter(x=>x.verificacionPendiente);
const olavarria=data.find(x=>x.tipo==="publico"&&x.localidad==="Olavarría");
const sanJusto=data.find(x=>x.tipo==="ja"&&x.localidad==="San Justo");

assert.equal(data.length,45);
assert.equal(data.filter(x=>x.tipo==="familias").length,4);
assert.equal(rowsWithWarnings.length,2);
assert.equal(olavarria.verificacionPendiente,"direccion");
assert.equal(sanJusto.verificacionPendiente,"horarios");
assert.equal(olavarria.fuente,"https://loteria.gba.gob.ar/node/522");
assert.equal(olavarria.fuenteAlternativa,"https://loteria.gba.gob.ar/juego-compulsivo");
assert.equal(sanJusto.fuente,"https://jugadoresanonimos.org.ar/buenos-aires-zona-oeste/");
assert.equal(sanJusto.fuenteAlternativa,"https://jugadoresanonimos.org.ar/location/san-justo/");
assert.ok(olavarria.nota.includes("Alsina 3157")&&olavarria.nota.includes("Hornos 2992"));
assert.ok(sanJusto.nota.includes("miércoles")&&sanJusto.nota.includes("martes"));
for(const row of data){
 assert.ok(types.has(row.tipo));
 assert.ok(["","direccion","horarios"].includes(row.verificacionPendiente||""));
 assert.ok(row.direccion.length>0&&row.localidad.length>0);
 assert.ok(row.fuente.startsWith("https://"));
 assert.ok(Array.isArray(row.horarios));
 assert.ok(!row.verificacionPendiente||row.nota,"Advertencia visible cuando falta verificación: "+row.localidad);
}
assert.ok(src.includes('verificacionPendiente?: "direccion"|"horarios"'));
assert.ok(src.includes('r.verificacionPendiente!=="horarios"&&r.horarios.some(h=>h.dia===day)'),"Horario incierto no debe habilitar filtro por día");
assert.ok(src.includes('r.verificacionPendiente==="horarios"?'),"Ocultar horarios contradictorios");
assert.ok(src.includes("Días y horarios en conflicto entre fuentes oficiales."),"Aviso de horario explícito");
assert.ok(src.includes('r.verificacionPendiente==="direccion"?'),"Ocultar indicaciones a dirección contradictoria");
assert.ok(src.includes("Ubicación a confirmar: no se muestran indicaciones"),"Indicación de incertidumbre en mapa");
assert.ok(src.includes("El filtro por día excluye los grupos cuyos horarios todavía presentan información contradictoria."),"Transparencia del filtro");
assert.ok(src.includes('r.fuenteAlternativa&&'),"Ambas fuentes permanecen visibles");
assert.ok(src.includes('r.nota&&'),"Advertencia permanece visible");
assert.ok(src.includes("Ver opciones y orientación"),"Siempre disponible ayuda alternativa");
assert.ok(src.includes("Enlaces y datos conflictivos contrastados el 3 de noviembre de 2026"),"Fecha de revisión limitada, no inventa verificación exhaustiva");
assert.doesNotMatch(src,/localStorage|sessionStorage|document\.cookie|sendBeacon|navigator\.geolocation|trackEvent|gtag/i);
console.log("VOLVE_DIRECTORY_UNCERTAINTY_OK",data.length,rowsWithWarnings.length);
