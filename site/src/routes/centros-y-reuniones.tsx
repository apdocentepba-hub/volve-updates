import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { PageHero, meta } from "@/components/ui-bits";
import entries from "@/data/ayuda-pba.json";
import { SupportStrip } from "@/components/SupportStrip";
import { toDialHref } from "@/lib/phone-link";

type Meeting = { dia: string; hora: string };
type Resource = { tipo: "publico"|"ja"|"familias"; zona: string; localidad: string; nombre: string; lugar: string; direccion: string; horarios: Meeting[]; telefono?: string; nota?: string; verificacionPendiente?: "direccion"|"horarios"; fuente: string; fuenteAlternativa?: string };
const data = entries as Resource[];
const types: Record<string,string> = { publico: "Centro público", ja: "Jugadores Anónimos", familias: "Para familiares · Jug-Anon" };
const zones: Record<string,string> = { sur:"Conurbano sur y La Plata", oeste:"Conurbano oeste", norte:"Conurbano norte", interior:"Interior provincial", Provincia:"Centros públicos" };
const norm=(s:string)=>s.normalize("NFD").replace(/[\u0300-\u036f]/g,"").toLocaleLowerCase("es");
type DirectorySearch = { tipo?: "publico" | "ja" | "familias" };
export const Route=createFileRoute("/centros-y-reuniones")({
 validateSearch:(search:Record<string,unknown>):DirectorySearch=>{
  const candidate=search.tipo;
  return typeof candidate==="string"&&Object.prototype.hasOwnProperty.call(types,candidate)
    ? {tipo:candidate as DirectorySearch["tipo"]}
    : {};
 },
 head:()=>meta("Centros y reuniones de ayuda en PBA — VOLVÉ","Buscá centros públicos gratuitos, Jugadores Anónimos, grupos familiares y reuniones virtuales.","/centros-y-reuniones"),
 component:Directory
});
function Directory(){
 const navigate=useNavigate({from:Route.fullPath});
 // Filtro validado por el router; al actualizar o compartir la URL, el resultado se conserva.
 const {tipo}=Route.useSearch();
 // Defensa adicional al leer: algunas transiciones del router exponen el valor
 // crudo antes de aplicar validateSearch. Nunca filtramos con valores no admitidos.
 const safeKind=typeof tipo==="string"&&Object.prototype.hasOwnProperty.call(types,tipo)?tipo:"";
 const [query,setQuery]=useState("");
 const [kind,setKind]=useState(safeKind);
 const [zone,setZone]=useState("");
 const [day,setDay]=useState("");
 useEffect(()=>setKind(safeKind),[safeKind]);
 function changeKind(next:string){
  setKind(next);
  void navigate({to:"/centros-y-reuniones",search:next?{tipo:next as DirectorySearch["tipo"]}:{},replace:true,hash:"buscar"});
 }
 function clearAll(){
  setQuery("");
  setKind("");
  setZone("");
  setDay("");
  void navigate({to:"/centros-y-reuniones",search:{},replace:true,hash:"buscar"});
 }
 const filtered=useMemo(()=>data.filter(r=>(!query||norm([r.localidad,r.nombre,r.lugar,r.direccion].join(" ")).includes(norm(query)))&&(!kind||r.tipo===kind)&&(!zone||r.zona===zone)&&(!day||(r.verificacionPendiente!=="horarios"&&r.horarios.some(h=>h.dia===day)))).sort((a,b)=>a.localidad.localeCompare(b.localidad,"es")),[query,kind,zone,day]);
 return <>
  <PageHero eyebrow="Asistencia gratuita · Provincia de Buenos Aires" title="Hay ayuda cerca. Y también desde casa." intro="Centros públicos, grupos presenciales, ayuda para familiares y reuniones virtuales. VOLVÉ no organiza estos encuentros ni tiene convenios con las entidades: confirmá los datos antes de asistir."/>
  <section className="container-v py-12">
    <h2 className="text-2xl font-bold text-primary">¿Necesitás orientación ahora?</h2>
    <div className="mt-6 grid gap-4 md:grid-cols-3">
      <a className="rounded-3xl bg-deep p-6 text-deep-foreground" href="tel:08004444000"><span className="text-sm opacity-80">Programa bonaerense de juego compulsivo</span><strong className="mt-3 block text-3xl">0800-444-4000</strong><p className="mt-3 text-sm opacity-80">Atención gratuita para personas y familias</p></a>
      <a className="rounded-3xl border border-border bg-card p-6" href="tel:08002225462"><span className="text-sm text-muted-foreground">Salud Mental de PBA</span><strong className="mt-3 block text-3xl text-primary">0800-222-5462</strong><p className="mt-3 text-sm text-muted-foreground">Orientación gratuita provincial</p></a>
      <a className="rounded-3xl border border-border bg-card p-6" href="tel:141"><span className="text-sm text-muted-foreground">SEDRONAR · Argentina</span><strong className="mt-3 block text-3xl text-primary">141</strong><p className="mt-3 text-sm text-muted-foreground">Orientación gratuita, las 24 horas</p></a>
    </div>
  </section>
  <section className="container-v py-8">
    <h2 className="text-3xl font-bold text-primary">Reuniones virtuales gratuitas</h2>
    <p className="mt-3 text-muted-foreground">Para participar o consultar por atención profesional virtual, verificá los datos y enlaces oficiales.</p>
    <div className="mt-6 grid gap-4 md:grid-cols-3">
      <article className="rounded-3xl border border-border bg-card p-6"><span className="text-sm font-bold text-sage">Jugadores Anónimos</span><h3 className="mt-3 text-xl font-bold text-primary">Todos los días · 19:00–21:00</h3><p className="my-4 text-sm text-muted-foreground">Reunión por internet, incluidos feriados. Hora argentina.</p><a href="https://jugadoresanonimos.org.ar/grupo-virtual/" target="_blank" rel="noopener noreferrer" className="text-primary font-semibold underline">Acceder a la información oficial ↗</a></article>
      <article className="rounded-3xl border border-border bg-card p-6"><span className="text-sm font-bold text-sage">Grupo juvenil de JA</span><h3 className="mt-3 text-xl font-bold text-primary">Martes · 21:00–22:30</h3><p className="my-4 text-sm text-muted-foreground">«Aprendiendo a Vivir», preferentemente hasta los 30 años.</p><a href="https://jugadoresanonimos.org.ar/grupo-virtual/" target="_blank" rel="noopener noreferrer" className="text-primary font-semibold underline">Confirmar el enlace vigente ↗</a></article>
      <article className="rounded-3xl border border-border bg-card p-6"><span className="text-sm font-bold text-sage">Programa público de PBA</span><h3 className="mt-3 text-xl font-bold text-primary">Unidad de Atención Virtual</h3><p className="my-4 text-sm text-muted-foreground">Asistencia profesional a distancia. Consultá cómo acceder al 0800-444-4000.</p><a href="https://loteria.gba.gob.ar/juego-compulsivo" target="_blank" rel="noopener noreferrer" className="text-primary font-semibold underline">Página del programa ↗</a></article>
    </div>
  </section>
  <section className="container-v py-12" id="buscar">
    <h2 className="text-3xl font-bold text-primary">Buscá un centro o una reunión</h2>
    {kind==="familias"&&<div className="mt-4 rounded-2xl border border-sage/60 bg-sage-soft p-4 text-sm text-primary">
      <p className="font-semibold">Estás viendo recursos específicos para familiares y amigos.</p>
      <p className="mt-1">También podés consultar los centros públicos o elegir otro tipo de apoyo.</p>
      <button type="button" onClick={clearAll} className="mt-3 min-h-11 rounded-full border border-primary px-4 py-2 font-semibold hover:bg-card">
        Mostrar todos los recursos
      </button>
    </div>}
    <p className="mt-3 text-muted-foreground">{filtered.length} recursos encontrados de {data.length} registrados en Buenos Aires. VOLVÉ no pide información personal ni gestiona turnos.</p>
    <div className="my-7 grid gap-3 rounded-3xl bg-sage-soft p-5 md:grid-cols-4">
      <label className="text-sm font-semibold">Localidad o dirección<input type="search" value={query} onChange={e=>setQuery(e.target.value)} placeholder="Ej.: Sarandí, Quilmes…" className="mt-2 w-full rounded-xl border border-border bg-card p-3 text-foreground"/></label>
      <label className="text-sm font-semibold">Tipo de ayuda<select value={kind} onChange={e=>changeKind(e.target.value)} className="mt-2 w-full rounded-xl border border-border bg-card p-3 text-foreground"><option value="">Todas</option>{Object.entries(types).map(([k,v])=><option key={k} value={k}>{v}</option>)}</select></label>
      <label className="text-sm font-semibold">Zona<select value={zone} onChange={e=>setZone(e.target.value)} className="mt-2 w-full rounded-xl border border-border bg-card p-3 text-foreground"><option value="">Toda la provincia</option>{Object.entries(zones).map(([k,v])=><option key={k} value={k}>{v}</option>)}</select></label>
      <label className="text-sm font-semibold">Día<select value={day} onChange={e=>setDay(e.target.value)} className="mt-2 w-full rounded-xl border border-border bg-card p-3 text-foreground"><option value="">Cualquier día</option>{["Lun","Mar","Mié","Jue","Vie","Sáb","Dom"].map(k=><option key={k}>{k}</option>)}</select></label>
    </div>
    {(query||kind||zone||day)&&<div className="mb-5 flex flex-wrap items-center gap-3 text-sm">
      <span className="text-muted-foreground">Filtros activos.</span>
      <button type="button" onClick={clearAll} className="min-h-11 rounded-full border border-primary px-5 py-2 font-semibold text-primary hover:bg-sage-soft">Limpiar todos los filtros</button>
    </div>}
    {day&&<p className="mb-5 text-sm text-muted-foreground">El filtro por día excluye los grupos cuyos horarios todavía presentan información contradictoria. Podés quitar ese filtro para verlos y consultar sus fuentes.</p>}
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
    {filtered.map((r,i)=><article key={r.localidad+r.direccion+i} className="rounded-3xl border border-border bg-card p-6">
      <p className="text-xs font-bold uppercase tracking-wide text-sage">{types[r.tipo]}</p>
      <h3 className="mt-2 text-xl font-bold text-primary">{r.localidad}</h3>
      <strong className="mt-2 block">{r.nombre}</strong>
      <p className="mt-2 text-sm text-muted-foreground">{r.lugar} · {r.direccion}</p>
      {r.verificacionPendiente==="horarios"?<p className="mt-3 rounded-xl border border-warm bg-warm-soft p-3 text-sm font-semibold text-accent-foreground">Días y horarios en conflicto entre fuentes oficiales. Consultá directamente con el grupo antes de ir.</p>:r.horarios.length?<p className="mt-3 text-sm">{r.horarios.map(h=>h.dia+" "+h.hora).join(" · ")}</p>:<p className="mt-3 text-sm text-muted-foreground">Consultá días y horarios de atención.</p>}
      {r.telefono&&<PhoneContact number={r.telefono}/>}
      {r.nota&&<p className="mt-3 rounded-xl bg-warm-soft p-3 text-xs text-accent-foreground">{r.nota}</p>}
      <div className="mt-5 flex flex-wrap gap-3 text-sm font-semibold text-primary">
        <a href={r.fuente} target="_blank" rel="noopener noreferrer" className="underline">Fuente oficial ↗</a>
        {r.fuenteAlternativa&&<a href={r.fuenteAlternativa} target="_blank" rel="noopener noreferrer" className="underline">Otra fuente ↗</a>}
        {r.verificacionPendiente==="direccion"?<span className="rounded-xl bg-warm-soft px-3 py-2 text-accent-foreground">Ubicación a confirmar: no se muestran indicaciones</span>:<a href={"https://www.google.com/maps/search/?api=1&query="+encodeURIComponent(r.direccion+", "+r.localidad+", Buenos Aires, Argentina")} target="_blank" rel="noopener noreferrer" className="underline">Cómo llegar ↗</a>}
      </div>
    </article>)}
    {!filtered.length&&<div className="rounded-3xl border border-border bg-card p-6 text-muted-foreground"><p>No encontramos resultados con esos filtros. Podés probar otra localidad o consultar al 0800-444-4000.</p><button type="button" onClick={clearAll} className="mt-4 min-h-11 rounded-full border border-primary px-5 py-2 font-semibold text-primary hover:bg-sage-soft">Mostrar los 45 recursos</button></div>}
    </div>
    <p className="mt-8 rounded-2xl bg-warm-soft p-5 text-sm text-accent-foreground">Los horarios y las sedes pueden cambiar. Verificá directamente con cada organización. El grupo «Catedral» de San Martín figura suspendido y no aparece aquí. Olavarría registra dos direcciones oficiales distintas: confirmá antes de ir.</p>
    <p className="mt-5 text-sm text-muted-foreground">¿Querés ayuda inmediata? <Link to="/ayuda" className="font-semibold text-primary underline">Ver opciones y orientación</Link> · Enlaces y datos conflictivos contrastados el 3 de noviembre de 2026; confirmá condiciones vigentes antes de asistir.</p>
  </section>
  <div className="container-v pb-12"><SupportStrip /></div>
 </>;
}

/** Botón voluntario: nunca reconstruimos números incompletos o solo de WhatsApp. */
function PhoneContact({number}:{number:string}) {
 const href=toDialHref(number);
 return <p className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-2 text-sm">
  <span>Teléfono: {number}</span>
  {href&&<a href={href} aria-label={"Llamar al "+number}
   className="inline-flex min-h-10 items-center rounded-full border border-primary px-4 py-2 font-semibold text-primary underline-offset-2 hover:bg-sage-soft focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary">
   Llamar
  </a>}
 </p>;
}
