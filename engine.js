/* Zero Trust Architect: deterministic educational simulation. */
const ZeroTrust = (function createEngine(){
 const controls=[
 ["mfa","Workforce MFA",18,"Identity","Verify employee sign-ins with a second factor."],
 ["pam","Privileged MFA & PAM",26,"Identity","Protect administrative access and use just-in-time elevation."],
 ["vendor","Vendor MFA",12,"Identity","Verify third-party access."],
 ["rbac","Least privilege",20,"Identity","Limit access to the minimum required role."],
 ["edr","Endpoint detection",23,"Endpoints","Detect and isolate compromised workstations."],
 ["patch","Patch management",16,"Endpoints","Reduce exposure to known vulnerabilities."],
 ["posture","Device compliance",15,"Endpoints","Require managed, compliant devices."],
 ["seg","Microsegmentation",25,"Network","Enforce explicit, verified network routes. Without this, route policies are advisory."],
 ["waf","Application gateway",18,"Network","Inspect inbound application traffic."],
 ["encrypt","Data encryption",16,"Data & recovery","Protect sensitive information at rest."],
 ["backup","Immutable backups",24,"Data & recovery","Recover from destructive incidents."],
 ["dlp","Data loss prevention",20,"Data & recovery","Detect and prevent unauthorised data transfers."],
 ["logs","Centralised logging",14,"Monitoring","Collect correlated security events."],
 ["response","Incident response",17,"Monitoring","Contain detected incidents. Requires centralised logging."]
 ].map(([id,name,cost,group,desc])=>({id,name,cost,group,desc}));
 const zones=[["staff","Workforce","Employee devices"],["vendor","Partner","External contractors"],["app","Applications","Business services"],["data","Data vault","Sensitive records"],["admin","Admin","Privileged operators"],["backup","Recovery","Backup repository"]];
 const routes=[
 ["staff-app","staff","app","Employee access",true],["vendor-app","vendor","app","Partner access",false],["app-data","app","data","Application queries",true],["admin-data","admin","data","Database maintenance",true],["app-backup","app","backup","Backup jobs",true],["admin-app","admin","app","Administration",true]
 ].map(([id,from,to,name,required])=>({id,from,to,name,required}));
 const threats=[
 {id:"phish",name:"Compromised employee credentials",weight:22,entry:"Employee account",prevent:[["mfa"],["posture"]],contain:[["edr","logs"],["seg","@staff-app","rbac"]],recover:[],lesson:"Verify identity and device posture, then limit the blast radius."},
 {id:"admin",name:"Privileged account abuse",weight:27,entry:"Admin account",prevent:[["pam"]],contain:[["rbac","logs","response"],["seg","@admin-data","rbac"]],recover:[],lesson:"Protect privileged identities and enforce narrow authorisation."},
 {id:"partner",name:"Compromised supplier",weight:19,entry:"Partner account",prevent:[["vendor"],["!vendor-app"]],contain:[["seg","@vendor-app","rbac"],["logs","response"]],recover:[],lesson:"Treat third-party access as untrusted and explicitly scoped."},
 {id:"ransom",name:"Ransomware outbreak",weight:30,entry:"Workforce device",prevent:[["patch","posture"]],contain:[["edr","logs"],["seg","@staff-app","@app-data"]],recover:[["backup"]],lesson:"Combine prevention, isolation and independently protected recovery."},
 {id:"app",name:"Exposed application flaw",weight:24,entry:"Public application",prevent:[["waf","patch"]],contain:[["seg","@app-data","rbac"],["logs","response"]],recover:[],lesson:"Protect the application boundary and restrict downstream access."},
 {id:"exfil",name:"Sensitive data exfiltration",weight:28,entry:"Compromised internal session",prevent:[["dlp","rbac"]],contain:[["dlp","logs"],["seg","@app-data","@admin-data","rbac"]],recover:[],lesson:"Apply data-aware controls. Encryption at rest does not stop an authorised session."},
 {id:"theft",name:"Stolen storage media",weight:15,entry:"Physical storage",prevent:[["encrypt"]],contain:[],recover:[],lesson:"Encryption at rest protects data when storage is lost or stolen."},
 {id:"backup",name:"Destructive backup tampering",weight:26,entry:"Backup repository",prevent:[["backup","pam"]],contain:[["seg","@app-backup","rbac"]],recover:[["backup"]],lesson:"Protect the recovery plane independently of production systems."}
 ];
 const scenarios=[
 {id:"studio",name:"Northstar Studio",type:"Small business",budget:128,description:"A growing design firm with remote employees and a sensitive client database. Protect daily operations without enterprise spending.",threats:["phish","admin","ransom","exfil","theft"],partner:false},
 {id:"clinic",name:"Meridian Health",type:"Healthcare",budget:175,description:"A fictional clinic with confidential records, supplier access and strict service continuity requirements.",threats:["phish","admin","partner","ransom","exfil","theft","backup"],partner:true},
 {id:"cloud",name:"Atlas Commerce",type:"Enterprise",budget:205,description:"A public-facing commerce platform with third-party integrations and critical recovery systems.",threats:["phish","admin","partner","ransom","app","exfil","backup"],partner:true}
 ];
 const findScenario=id=>scenarios.find(s=>s.id===id)||scenarios[0];
 const empty=()=>({controls:[],routes:Object.fromEntries(routes.map(r=>[r.id,"open"]))});
 function cost(d){return controls.filter(c=>d.controls.includes(c.id)).reduce((a,c)=>a+c.cost,0)+routes.filter(r=>d.routes[r.id]==="verified").length*4}
 function sanitise(raw,s){
  const d=empty();if(!raw||typeof raw!=="object")return d;
  if(Array.isArray(raw.controls))for(const c of controls){if(raw.controls.includes(c.id)&&cost(d)+c.cost<=s.budget)d.controls.push(c.id)}
  for(const r of routes){const p=raw.routes?.[r.id];if(p==="denied"||(p==="verified"&&cost(d)+4<=s.budget))d.routes[r.id]=p}
  return d;
 }
 function change(d,s,kind,id,value){
  const next={controls:[...d.controls],routes:{...d.routes}};
  if(kind==="control"&&controls.some(c=>c.id===id)){next.controls=next.controls.includes(id)?next.controls.filter(x=>x!==id):[...next.controls,id]}
  else if(kind==="route"&&routes.some(r=>r.id===id)&&["open","verified","denied"].includes(value)){next.routes[id]=value}
  else return {ok:false,reason:"Invalid configuration."};
  return cost(next)>s.budget?{ok:false,reason:"Insufficient budget. Remove a control or verified route first."}:{ok:true,design:next};
 }
 function evaluate(d,s){
  const has=id=>d.controls.includes(id);
  const gate=id=>id.startsWith("@")?has("seg")&&d.routes[id.slice(1)]==="verified":id.startsWith("!")?has("seg")&&d.routes[id.slice(1)]==="denied":has(id);
  const match=sets=>sets.find(set=>set.every(gate));
  const results=s.threats.map(id=>{
   const t=threats.find(x=>x.id===id),p=match(t.prevent),c=match(t.contain),r=match(t.recover);
   const status=p?"Prevented":c?"Contained":r?"Recovered":"Compromised";
   const factor=p?0:c?0.35:r?0.65:1;
   return {...t,status,loss:t.weight*factor,matched:p||c||r||[],missing:p||c||r?[]:(t.prevent[0]||[]).filter(x=>!gate(x))};
  });
  const total=results.reduce((a,t)=>a+t.weight,0),loss=results.reduce((a,t)=>a+t.loss,0);
  const security=Math.round(100*(1-loss/total));
  const required=routes.filter(r=>r.required||(r.id==="vendor-app"&&s.partner));
  const broken=required.filter(r=>has("seg")&&d.routes[r.id]==="denied");
  const availability=Math.round(100*(1-broken.length/required.length));
  const score=Math.round(security*0.75+availability*0.25);
  return {results,security,availability,score,broken:broken.map(r=>r.name),spent:cost(d)};
 }
 function label(id){if(id.startsWith("@"))return routes.find(r=>r.id===id.slice(1)).name+" verified";if(id.startsWith("!"))return routes.find(r=>r.id===id.slice(1)).name+" denied";return controls.find(c=>c.id===id)?.name||id}
 return {controls,zones,routes,threats,scenarios,findScenario,empty,cost,sanitise,change,evaluate,label};
})();
if(typeof module !== "undefined")module.exports=ZeroTrust;
