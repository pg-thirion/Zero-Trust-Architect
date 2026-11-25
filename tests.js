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
