import assert from "node:assert/strict";
import {chromium} from "playwright";

const site=process.env.VOLVE_TEST_ORIGIN||"http://127.0.0.1:4173";
const browser=await chromium.launch({headless:true,args:["--no-sandbox"]});
const page=await browser.newPage({viewport:{width:390,height:844},deviceScaleFactor:1});
page.on("pageerror",err=>console.error("PAGE_ERROR:",err.message));

const results=async()=>page.locator("#buscar article").count();
const go=async(url,expected)=>{
  const r=await page.goto(site+url,{waitUntil:"domcontentloaded",timeout:30000});
  assert.equal(r?.status(),200,"Page reachable: "+url);
  await page.locator("#buscar").getByText(new RegExp(expected+" recursos encontrados")).waitFor({timeout:10000});
  assert.equal(await results(),expected,"Results for "+url);
  console.log("BROWSER_RESULT_OK",url,expected);
};

try {
  await go("/centros-y-reuniones",45);
  await go("/centros-y-reuniones?tipo=invalido",45);
  await go("/centros-y-reuniones?tipo=constructor",45);
  await go("/centros-y-reuniones?tipo=ja",31);
  await go("/centros-y-reuniones?tipo=familias#buscar",4);
  assert.equal(await page.locator("#buscar").getByText(/Estás viendo recursos específicos para familiares/).count(),1);

  // El botón que antes sólo limpiaba el tipo debe limpiar también búsqueda/zona/día
  await page.getByLabel("Localidad o dirección").fill("Lanús");
  await page.getByLabel("Zona").selectOption("sur");
  await page.getByLabel("Día").selectOption("Mié");
  await page.locator("#buscar").getByText(/1 recursos encontrados/).waitFor({timeout:10000});
  await page.getByRole("button",{name:"Mostrar todos los recursos"}).click();
  await page.locator("#buscar").getByText(/45 recursos encontrados/).waitFor({timeout:10000});
  assert.equal(await results(),45,"Full reset should clear all criteria");
  assert.equal(new URL(page.url()).searchParams.has("tipo"),false,"Reset URL not stale");
  await page.reload({waitUntil:"domcontentloaded"});
  await page.locator("#buscar").getByText(/45 recursos encontrados/).waitFor({timeout:10000});
  console.log("RESET_RELOAD_OK",page.url());

  // Elegir un tipo desde el selector debe ser compartible y sobrevivir reload.
  await page.getByLabel("Tipo de ayuda").selectOption("ja");
  await page.locator("#buscar").getByText(/31 recursos encontrados/).waitFor({timeout:10000});
  assert.equal(new URL(page.url()).searchParams.get("tipo"),"ja","Category persisted to URL");
  await page.reload({waitUntil:"domcontentloaded"});
  await page.locator("#buscar").getByText(/31 recursos encontrados/).waitFor({timeout:10000});
  console.log("CATEGORY_RELOAD_OK",page.url());

  // Búsqueda vacía: botón para volver a los 45 recursos.
  await page.getByLabel("Localidad o dirección").fill("No existe xyz 2026");
  await page.locator("#buscar").getByText(/0 recursos encontrados/).waitFor({timeout:10000});
  await page.getByRole("button",{name:"Mostrar los 45 recursos"}).click();
  await page.locator("#buscar").getByText(/45 recursos encontrados/).waitFor({timeout:10000});
  assert.equal(new URL(page.url()).searchParams.has("tipo"),false);
  console.log("ZERO_RESULTS_RECOVERY_OK");

  await go("/centros-y-reuniones?tipo=familias",4);
  await page.setViewportSize({width:375,height:812});
  const button=page.getByRole("button",{name:"Mostrar todos los recursos"});
  assert.equal(await button.isVisible(),true);
  const bodyScroll=await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth+2);
  assert.equal(bodyScroll,false,"Directory should not overflow mobile viewport");
  console.log("MOBILE_375_OK");
} finally {
  await browser.close();
}
