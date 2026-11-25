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
