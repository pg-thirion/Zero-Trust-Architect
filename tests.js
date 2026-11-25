/* Run with node tests.js */
const E = require("./engine.js");
const count = (function test(E){
 let n=0;function check(x,msg){if(!x)throw Error(msg);n++}
 function make(s,ids,policies={}){let d=E.empty();for(const id of ids){let r=E.change(d,s,"control",id);check(r.ok,"affordable: "+id);d=r.design}for(const [id,p] of Object.entries(policies)){let r=E.change(d,s,"route",id,p);check(r.ok,"affordable route");d=r.design}return d}
 for(const s of E.scenarios){
  const d=E.empty(),r=E.evaluate(d,s);check(r.score===25,"baseline");check(r.security===0,"baseline security");check(r.availability===100,"baseline business");check(r.results.length===s.threats.length,"threat suite");check(E.cost(d)===0,"zero budget");check(E.change(d,s,"control","bogus").ok===false,"unknown control");check(E.change(d,s,"route","staff-app","bogus").ok===false,"unknown policy");
  const all=E.sanitise({controls:E.controls.map(c=>c.id),routes:Object.fromEntries(E.routes.map(r=>[r.id,"verified"]))},s);check(E.cost(all)<=s.budget,"sanitise budget");check(E.evaluate(all,s).security>0,"investments reduce risk");check(E.sanitise({controls:["mfa","mfa","fake"]},s).controls.length===1,"duplicate control");check(E.evaluate(d,s).score===E.evaluate(d,s).score,"deterministic");check(E.change({controls:E.controls.map(c=>c.id),routes:d.routes},s,"route","staff-app","verified").ok===false,"reject overspend");check(E.evaluate(make(s,["seg"],{"staff-app":"denied"}),s).availability<100,"blocked business");check(E.evaluate(make(s,[],{"staff-app":"denied"}),s).availability===100,"advisory only");
 }
 const s=E.scenarios[1],out=(d,id)=>E.evaluate(d,s).results.find(t=>t.id===id).status;
 check(out(make(s,["mfa"]),"phish")==="Prevented","employee MFA");check(out(make(s,["pam"]),"admin")==="Prevented","privileged MFA");check(out(make(s,["vendor"]),"partner")==="Prevented","supplier MFA");
 check(out(make(s,["seg"],{"vendor-app":"denied"}),"partner")==="Prevented","deny partner");check(E.evaluate(make(s,["seg"],{"vendor-app":"denied"}),s).availability<100,"partner required");
 check(out(make(s,["edr","logs"]),"ransom")==="Contained","EDR logging");check(out(make(s,["backup"]),"ransom")==="Recovered","backup recovery");check(out(make(s,["encrypt"]),"theft")==="Prevented","encryption");check(out(make(s,["response"]),"phish")==="Compromised","response needs logs");
 check(out(make(s,["rbac","dlp"]),"exfil")==="Prevented","DLP");check(out(make(s,["seg","rbac"],{"admin-data":"verified"}),"admin")==="Contained","verified admin route");
 const d=make(s,["mfa"]);check(E.change(d,s,"control","mfa").design.controls.length===0,"refund");check(d.controls.length===1,"immutable input");
 check(E.sanitise(null,s).controls.length===0,"invalid save");return n;
})(E);
console.log(count + " engine checks passed");

const propertyCount = (function propertyChecks(E){
 let checks=0,seed=42013;
 function assert(condition,message){if(!condition)throw Error(message);checks++}
 function rand(n){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return (seed>>>8)%n}
 for(const s of E.scenarios){
  const baseline=E.empty();
  assert(E.evaluate(E.sanitise({controls:["posture"]},s),s).results.find(x=>x.id==="phish").status==="Compromised","device compliance alone must not stop credential compromise");
  for(let i=0;i<500;i++){
   let d=E.empty();
   for(let j=0;j<25;j++){
    const control=rand(2)===0;
    const id=control?E.controls[rand(E.controls.length)].id:E.routes[rand(E.routes.length)].id;
    const input=JSON.stringify(d);
    const next=E.change(d,s,control?"control":"route",id,["open","verified","denied"][rand(3)]);
    assert(JSON.stringify(d)===input,"change cannot mutate prior design");
    if(next.ok)d=next.design;
    assert(E.cost(d)>=0&&E.cost(d)<=s.budget,"budget invariant");
   }
   const r=E.evaluate(d,s);
   assert(r.score>=0&&r.score<=100&&r.security>=0&&r.security<=100&&r.availability>=0&&r.availability<=100,"score bounds");
   assert(r.score===Math.round(r.security*.75+r.availability*.25),"weighted score");
   assert(r.spent===E.cost(d),"report cost");
   assert(JSON.stringify(E.evaluate(d,s))===JSON.stringify(r),"deterministic results");
   assert(JSON.stringify(E.sanitise(d,s).routes)===JSON.stringify(d.routes),"route persistence");
   assert(E.cost(E.sanitise(d,s))===E.cost(d),"control persistence");
   assert(r.results.every(x=>["Prevented","Contained","Recovered","Compromised"].includes(x.status)&&x.loss>=0&&x.loss<=x.weight),"valid outcomes");
   if(!d.controls.includes("seg"))assert(r.availability===100,"advisory policies cannot cause outages");
  }
 }
 return checks;
})(E);
console.log(propertyCount + ' seeded invariant checks passed');

const v2Count = (function expandedChecks(E){
 let n=0;function check(x,msg){if(!x)throw Error(msg);n++}
 check(E.scenarios.length===6,"six missions");check(E.controls.length===24,"24 controls");check(E.threats.length===16,"16 threats");
 for(const list of [E.controls,E.threats,E.scenarios,E.routes])check(new Set(list.map(x=>x.id)).size===list.length,"unique IDs");
 const allIds=new Set(E.controls.map(c=>c.id));
 for(const t of E.threats)for(const group of [t.prevent,t.contain,t.recover])for(const rule of group)for(const item of rule)check(item.startsWith("@")||item.startsWith("!")?E.routes.some(r=>r.id===item.slice(1)):allIds.has(item),"valid threat rule "+item);
 for(const s of E.scenarios){
  for(const id of s.threats)check(E.threats.some(t=>t.id===id),"valid mission threat");
  for(const m of E.modes){
   const sc=E.mission(s.id,m.id);check(sc.budget===Math.round(s.budget*m.factor),"difficulty budget");check(sc.target===m.target,"difficulty target");
   check(E.key(sc)===(m.id==="standard"?s.id:s.id+"-"+m.id),"distinct save key");
   const blank=E.empty();check(!E.verifyRoutes(blank,sc).ok,"segmentation dependency");
   for(const p of E.presets){
    const d=E.blueprint(p.id,sc);check(E.cost(d)<=sc.budget,"preset budget");check(d.controls.length>0,"nonempty template");
    const encoded=E.exportDesign(d,sc),result=E.importDesign(JSON.parse(JSON.stringify(encoded)));
    check(result&&result.scenario.id===sc.id&&result.scenario.difficulty===sc.difficulty,"import mission and mode");
    check(result.design.controls.every(c=>d.controls.includes(c))&&E.cost(result.design)===E.cost(d),"round-trip design");
    const a=E.insights(d,sc);check(a.objectives.length===5,"objective count");check(a.maturity.reduce((v,g)=>v+g.installed,0)===d.controls.length,"coverage count");
    check(a.risk.every((t,i)=>i===0||a.risk[i-1].loss>=t.loss),"risk ordering");
    check(a.exposure.open+a.exposure.verified+a.exposure.denied===E.routes.length,"route accounting");
    check(a.improvement===a.report.score-E.evaluate(blank,sc).score,"baseline comparison");
    check(a.efficiency===Math.round(a.improvement*100/E.cost(d))/100,"efficiency");
    if(a.recommendation){const rec=a.recommendation,next=E.change(d,sc,rec.kind,rec.id,"verified");check(next.ok,"affordable recommendation");check(E.evaluate(next.design,sc).score-a.report.score===rec.gain&&rec.gain>0,"accurate recommendation")}
   }
   const segmented=E.change(blank,sc,"control","seg").design,verified=E.verifyRoutes(segmented,sc);check(verified.ok,"verify all");
   check(E.routes.every(r=>verified.design.routes[r.id]===(E.required(r,sc)?"verified":"denied")),"enforce required and deny optional");
   check(E.evaluate(verified.design,sc).availability===100,"verified business continuity");
   const over={...sc,budget:25};check(!E.verifyRoutes(segmented,over).ok,"no partial bulk change");
   check(E.evaluateOne(blank,sc,"not-real")===null,"invalid threat");
   for(const t of E.threats){const actual=E.evaluateOne(blank,sc,t.id);check(actual.status==="Compromised"&&actual.loss===t.weight,"single threat baseline")}
  }
 }
 const budget={...E.mission("bank"),budget:1000};
 for(const t of E.threats){
  for(const [type,sets] of [["Prevented",t.prevent],["Contained",t.contain],["Recovered",t.recover]])for(const set of sets){
   let d=E.empty();for(const item of set){if(item.startsWith("@")||item.startsWith("!")){if(!d.controls.includes("seg"))d=E.change(d,budget,"control","seg").design;d=E.change(d,budget,"route",item.slice(1),item.startsWith("@")?"verified":"denied").design}else if(!d.controls.includes(item))d=E.change(d,budget,"control",item).design}
   const actual=E.evaluateOne(d,budget,t.id);const rank=["Compromised","Recovered","Contained","Prevented"];check(rank.indexOf(actual.status)>=rank.indexOf(type),"rule produces outcome "+t.id);
  }
 }
 const sc=E.mission("studio"),raw=E.exportDesign(E.empty(),sc);
 for(const bad of [null,{}, {...raw,version:1},{...raw,mission:"unknown"},{...raw,difficulty:"bad"},{...raw,design:{controls:["bogus"],routes:raw.design.routes}},{...raw,design:{controls:["mfa","mfa"],routes:raw.design.routes}},{...raw,design:{controls:E.controls.map(c=>c.id),routes:raw.design.routes}},{...raw,design:{controls:[],routes:{...raw.design.routes,"staff-app":"bad"}}},{...raw,design:{controls:[],routes:{...raw.design.routes,extra:"open"}}}])check(E.importDesign(bad)===null,"reject invalid design");
 check(E.blueprint("unknown",sc)===null,"unknown preset");
 return n;
})(E);
console.log(v2Count + ' expanded feature checks passed');
