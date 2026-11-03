import assert from "node:assert/strict";
import {chromium} from "playwright";

const base=process.env.VOLVE_TEST_ORIGIN||"http://127.0.0.1:4173";
const browser=await chromium.launch({headless:true,args:["--no-sandbox"]});
const page=await browser.newPage({viewport:{width:390,height:844},deviceScaleFactor:1});
const outbound=[];
await page.route(/(?:visitor-badge\.one9x\.com|fonts\.googleapis\.com|fonts\.gstatic\.com)/,async route=>{
  outbound.push(route.request().url());
  await route.abort(); // no third-party traffic or artificial visit from CI
});
try{
 let r=await page.goto(base+"/preguntas",{waitUntil:"domcontentloaded"});
 assert.equal(r?.status(),200);
 const faq=page.locator("details").filter({hasText:"¿Puedo aportar?"});
 assert.equal(await faq.count(),1);
 await faq.locator("summary").click();
 const answer=await faq.innerText();
 assert.match(answer,/Sí\. En la sección Colaborá/,"Visible FAQ must reflect active donation options");
 assert.match(answer,/comprobá el destinatario/i,"Donation FAQ includes recipient check");
 assert.doesNotMatch(answer,/Pronto\. El canal/);
 const privacy=page.locator("details").filter({hasText:"¿Qué pasa con mi privacidad?"});
 await privacy.locator("summary").click();
 const privacyText=await privacy.innerText();
 assert.match(privacyText,/Visitor Badge/);
 assert.match(privacyText,/dirección IP/);
 assert.match(privacyText,/sessionStorage/);
 assert.match(privacyText,/Google Fonts/);
 const footer=await page.locator("footer").innerText();
 assert.match(footer,/servicio externo Visitor Badge/);
 console.log("VOLVE_FAQ_PRIVACY_BROWSER_OK");

 r=await page.goto(base+"/centros-y-reuniones",{waitUntil:"domcontentloaded"});
 assert.equal(r?.status(),200);
 const strip=await page.getByRole("complementary",{name:"Colaborar con el proyecto VOLVÉ"}).innerText();
 assert.match(strip,/Los aportes económicos son voluntarios/);
 assert.doesNotMatch(strip,/todavía no están habilitados/);
 console.log("VOLVE_SUPPORT_STRIP_BROWSER_OK");

 r=await page.goto(base+"/colabora",{waitUntil:"domcontentloaded"});
 assert.equal(r?.status(),200);
 await page.getByText("Canales habilitados").waitFor();
 assert.equal(await page.locator('a[href="https://cafecito.app/volve"]').count()>0,true);
 assert.equal(await page.locator('a[href="https://link.mercadopago.com.ar/volve"]').count()>0,true);
 assert.equal(await page.getByLabel("Alias para transferencia").inputValue(),"volve.prevencion");
 assert.match(await page.innerText("body"),/Proyectos Independientes/);
 console.log("VOLVE_DONATIONS_BROWSER_OK");
 assert.ok(outbound.some(x=>x.includes("visitor-badge.one9x.com")),"Evidence counter contacts third party automatically");
 console.log("VOLVE_THIRD_PARTY_DISCLOSURE_CONFIRMED",outbound.length);
}finally{await browser.close();}
