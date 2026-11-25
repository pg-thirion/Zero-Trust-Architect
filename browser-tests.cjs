"use strict";
// Development-only browser smoke tests; requires playwright-core and Chrome.
const {chromium}=require("playwright-core");
const assert=require("node:assert/strict");
const http=require("node:http");
const fs=require("node:fs");
const path=require("node:path");
const {once}=require("node:events");
const files={"index.html":"text/html","styles.css":"text/css","engine.js":"text/javascript","app.js":"text/javascript","favicon.svg":"image/svg+xml"};
const server=http.createServer((req,res)=>{
 const name=new URL(req.url,"http://localhost").pathname.slice(1)||"index.html";
 if(!Object.hasOwn(files,name)){res.writeHead(404);return res.end()}
 res.writeHead(200,{"Content-Type":files[name]+"; charset=utf-8","X-Content-Type-Options":"nosniff"});
 res.end(fs.readFileSync(path.join(__dirname,name)));
});
async function main(){
 server.listen(0,"127.0.0.1");await once(server,"listening");
 const browser=await chromium.launch({channel:"chrome",headless:true,args:["--no-sandbox"]});
 try{
 const base="http://127.0.0.1:"+server.address().port;
 let checks=0;
 const check=(condition,message)=>{assert.ok(condition,message);checks++};
 for(const viewport of [{width:1440,height:900},{width:1024,height:768},{width:390,height:844},{width:320,height:640}]){
  const page=await browser.newPage({viewport,acceptDownloads:true});
  const errors=[];
  page.on("pageerror",e=>errors.push(e.message));
  page.on("console",m=>{if(m.type()==="error")errors.push(m.text())});
  await page.goto(base);
  await page.locator("#boot-message").waitFor({state:"hidden"});
  check(await page.locator("#budget").textContent()==="$128k","initial budget");
  check(await page.locator("#network-svg .node-box").count()===6,"network zones");
  check(await page.locator("[data-control]").count()===14,"control count");
  check(await page.locator("[data-route]").count()===6,"route count");
  check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),"no horizontal page overflow at "+viewport.width);
  await page.locator("#c-mfa").click();
  check(await page.locator("#budget").textContent()==="$110k","MFA cost");
  await page.locator("#c-seg").click();
  await page.locator("#r-staff-app").selectOption("denied");
  check(await page.locator("#seg-status").textContent()==="Enforced","segmentation active");
  await page.locator("#run").click();
  check((await page.locator("#report").innerText()).includes("Disrupted services: Employee access"),"service disruption");
  check((await page.locator("#report").innerText()).includes("Prevented"),"prevented incident");
  check(await page.locator(".incident").count()===5,"incident count");
  await page.locator(".incident summary").first().click();
  check(await page.locator(".incident").first().getAttribute("open")!==null,"incident detail");
  const downloadPromise=page.waitForEvent("download");
  await page.locator("#export").click();
  const download=await downloadPromise;
  check(download.suggestedFilename()==="zero-trust-studio-report.txt","report filename");
  const content=fs.readFileSync(await download.path(),"utf8");
  check(content.includes("Workforce MFA")&&content.includes("Employee access: denied"),"report contents");
  await page.locator("#r-staff-app").selectOption("verified");
  check(await page.locator("#export").isDisabled(),"stale report invalidated");
  check(await page.locator("#budget").textContent()==="$81k","verified route cost");
  await page.reload();
  await page.locator("#boot-message").waitFor({state:"hidden"});
  check(await page.locator("#budget").textContent()==="$81k","design persisted");
  check(await page.locator("#r-staff-app").inputValue()==="verified","policy persisted");
  check(await page.locator("#best").textContent()!=="—","best persisted");
  await page.locator('[data-mission="clinic"]').click();
  check(await page.locator("#budget").textContent()==="$175k","mission isolation");
  await page.locator("#run").click();
  check(await page.locator(".incident").count()===7,"clinic threat suite");
  await page.locator('[data-mission="cloud"]').click();
  check(await page.locator("#budget").textContent()==="$205k","enterprise budget");
  await page.locator("#run").click();
  check(await page.locator(".incident").count()===7,"enterprise threat suite");
  await page.locator('[data-mission="studio"]').click();
  check(await page.locator("#budget").textContent()==="$81k","return to saved design");
  page.once("dialog",d=>d.accept());
  await page.locator("#reset").click();
  check(await page.locator("#budget").textContent()==="$128k","reset refunded");
  check(await page.locator("#best").textContent()!=="—","reset retains best score");
  for(const id of ["pam","backup","edr","seg","rbac"])await page.locator("#c-"+id).click();
  check(Number((await page.locator("#budget").textContent()).replace(/[^0-9]/g,""))>=0,"budget nonnegative");
  check(await page.locator("#c-mfa").getAttribute("aria-disabled")==="true","unaffordable state");
  await page.evaluate(()=>localStorage.setItem("zta-v1","{malformed"));
  await page.reload();
  await page.locator("#boot-message").waitFor({state:"hidden"});
  check(await page.locator("#budget").textContent()==="$128k","malformed storage recovery");
  check(errors.length===0,"browser errors: "+errors.join("; "));
  await page.close();
 }
 console.log(checks+" real-browser checks passed");
 }finally{await browser.close()}
}
main().catch(e=>{console.error(e);process.exitCode=1}).finally(()=>server.close());
