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
 {id:"phish",name:"Compromised employee credentials",weight:22,entry:"Employee account",prevent:[["mfa"]],contain:[["edr","logs"],["seg","@staff-app","rbac"]],recover:[],lesson:"Require MFA to protect stolen credentials, then verify devices and limit the blast radius."},
 {id:"admin",name:"Privileged account abuse",weight:27,entry:"Admin account",prevent:[["pam"]],contain:[["rbac","logs","response"],["seg","@admin-data","rbac"]],recover:[],lesson:"Protect privileged identities and enforce narrow authorisation."},
 {id:"partner",name:"Compromised supplier",weight:19,entry:"Partner account",prevent:[["vendor"],["!vendor-app"]],contain:[["seg","@vendor-app","rbac"],["logs","response"]],recover:[],lesson:"Treat third-party access as untrusted and explicitly scoped."},
 {id:"ransom",name:"Ransomware outbreak",weight:30,entry:"Workforce device",prevent:[["patch","posture"]],contain:[["edr","logs"],["seg","@staff-app","@app-data","rbac"]],recover:[["backup"]],lesson:"Combine prevention, isolation and independently protected recovery."},
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

 const moreControls=[
 ["fido","Phishing-resistant MFA",28,"Identity","Use hardware-backed authentication resistant to credential phishing."],
 ["session","Continuous session checks",19,"Identity","Re-evaluate active sessions and revoke risky tokens."],
 ["workload","Workload identity",20,"Identity","Use short-lived service identities instead of shared secrets."],
 ["inventory","Asset inventory",11,"Endpoints","Discover unmanaged assets and identify ownership."],
 ["allowlist","Application allowlisting",17,"Endpoints","Restrict execution to approved software."],
 ["dns","DNS filtering",10,"Network","Block known malicious domains at the resolver."],
 ["egress","Egress filtering",14,"Network","Restrict outbound traffic to approved destinations."],
 ["keys","Key management",18,"Data & recovery","Separate key access from data access and rotate keys."],
 ["restore","Recovery drills",12,"Data & recovery","Practise restoration and validate recovery procedures."],
 ["siem","Behaviour analytics",21,"Monitoring","Identify anomalous activity using correlated telemetry."]
 ];
 controls.push(...moreControls.map(([id,name,cost,group,desc])=>({id,name,cost,group,desc})));
 threats.find(t=>t.id==="phish").prevent.push(["fido"]);
 threats.find(t=>t.id==="ransom").contain.push(["allowlist","edr"]);
 threats.find(t=>t.id==="exfil").contain.push(["egress","logs","dlp"]);
 const extra=[
 {id:"token",name:"Stolen session token",weight:24,entry:"Active employee session",prevent:[["session","posture"]],contain:[["session","logs"],["rbac","siem","logs"]],recover:[],lesson:"MFA at login cannot protect every active session. Reassess and revoke risky sessions."},
 {id:"service",name:"Leaked service credentials",weight:26,entry:"Application identity",prevent:[["workload","rbac"]],contain:[["seg","@app-data","rbac"],["logs","response"]],recover:[],lesson:"Use short-lived workload identities and scope their permissions."},
 {id:"shadow",name:"Unmanaged device access",weight:20,entry:"Unregistered endpoint",prevent:[["inventory","posture"]],contain:[["seg","@staff-app","rbac"],["edr","logs"]],recover:[],lesson:"Maintain an asset inventory and enforce device compliance."},
 {id:"malware",name:"Unauthorised software execution",weight:23,entry:"Workstation",prevent:[["allowlist"]],contain:[["edr","logs"],["dns","egress"]],recover:[["backup","restore"]],lesson:"Restrict software execution and detect unusual endpoint behaviour."},
 {id:"beacon",name:"Suspicious outbound traffic",weight:21,entry:"Compromised endpoint",prevent:[["dns","egress"]],contain:[["egress","logs"],["edr","siem","logs"]],recover:[],lesson:"Constrain outbound traffic and monitor deviations."},
 {id:"key",name:"Sensitive key exposure",weight:25,entry:"Data vault",prevent:[["keys","rbac"]],contain:[["keys","logs","response"]],recover:[],lesson:"Keep key access independent from ordinary data access."},
 {id:"recovery",name:"Failed disaster recovery",weight:32,entry:"Recovery infrastructure",prevent:[["backup","restore"]],contain:[],recover:[["backup"]],lesson:"Backups alone do not guarantee a working recovery. Practise restores."},
 {id:"insider",name:"Anomalous insider activity",weight:28,entry:"Trusted employee account",prevent:[["rbac","dlp"]],contain:[["siem","logs","response"],["dlp","logs"]],recover:[],lesson:"Monitor behaviour and minimise legitimate access to sensitive data."}
 ];
 threats.push(...extra);
 scenarios.push(
 {id:"university",name:"Harbour University",type:"Education",budget:195,description:"A distributed campus with shared devices and external researchers. Maintain access while controlling unmanaged endpoints.",threats:["phish","shadow","token","malware","beacon","exfil","insider"],partner:true},
 {id:"bank",name:"Cobalt Finance",type:"Financial services",budget:245,description:"A fictional financial institution with valuable records and high-risk service identities.",threats:["phish","admin","token","service","key","exfil","insider","backup"],partner:true},
 {id:"factory",name:"Ironwood Manufacturing",type:"Industrial enterprise",budget:225,description:"A manufacturer that depends on reliable production systems, suppliers and recovery infrastructure.",threats:["phish","partner","shadow","malware","beacon","ransom","recovery","backup"],partner:true}
 );
 const modes=[{id:"training",name:"Training",factor:1.25,target:70},{id:"standard",name:"Standard",factor:1,target:75},{id:"expert",name:"Expert",factor:.8,target:80}];
 const presets=[
 {id:"identity",name:"Identity first",ids:["mfa","pam","rbac","vendor","posture","session","workload"]},
 {id:"resilience",name:"Recovery first",ids:["backup","restore","edr","logs","patch","response","encrypt"]},
 {id:"network",name:"Network first",ids:["seg","rbac","waf","egress","dns","logs"]},
 {id:"balanced",name:"Balanced",ids:["mfa","pam","backup","rbac","logs","edr","encrypt","seg"]}
 ];
 const mode=id=>modes.find(x=>x.id===id)||modes[1];
 function mission(id,difficulty="standard"){const s=findScenario(id),m=mode(difficulty);return {...s,budget:Math.round(s.budget*m.factor),difficulty:m.id,target:m.target}}
 const key=(s)=>s.id+(s.difficulty&&s.difficulty!=="standard"?"-"+s.difficulty:"");
 const required=(r,s)=>r.required||(r.id==="vendor-app"&&s.partner);
 function verifyRoutes(d,s){let next={controls:[...d.controls],routes:{...d.routes}};if(!next.controls.includes("seg"))return {ok:false,reason:"Install microsegmentation first."};for(const r of routes)next.routes[r.id]=required(r,s)?"verified":"denied";return cost(next)<=s.budget?{ok:true,design:next}:{ok:false,reason:"Insufficient budget to verify all required routes."}}
 function blueprint(id,s){const p=presets.find(x=>x.id===id);if(!p)return null;let d=empty();for(const c of p.ids){const n=change(d,s,"control",c);if(n.ok)d=n.design}if(d.controls.includes("seg")){const n=verifyRoutes(d,s);if(n.ok)d=n.design}return d}
 function evaluateOne(d,s,id){if(!threats.some(t=>t.id===id))return null;return evaluate(d,{...s,threats:[id]}).results[0]}
 function insights(d,s){
  const report=evaluate(d,s),base=evaluate(empty(),s),spent=cost(d);
  const risk=report.results.slice().sort((a,b)=>b.loss-a.loss||b.weight-a.weight);
  const objectives=[
   {name:"Reach mission score "+(s.target||75),met:report.score>=(s.target||75)},
   {name:"Preserve all critical services",met:report.availability===100},
   {name:"Enforce verified critical routes",met:d.controls.includes("seg")&&routes.filter(r=>required(r,s)).every(r=>d.routes[r.id]==="verified")},
   {name:"Protect employee and admin identities",met:(d.controls.includes("mfa")||d.controls.includes("fido"))&&d.controls.includes("pam")},
   {name:"Maintain recovery capability",met:d.controls.includes("backup")}
  ];
  const candidates=[];
  for(const c of controls){if(d.controls.includes(c.id))continue;const n=change(d,s,"control",c.id);if(n.ok){const v=evaluate(n.design,s).score-report.score;if(v>0)candidates.push({kind:"control",id:c.id,name:c.name,cost:c.cost,gain:v})}}
  if(d.controls.includes("seg"))for(const r of routes){if(d.routes[r.id]==="verified")continue;const n=change(d,s,"route",r.id,"verified");if(n.ok){const v=evaluate(n.design,s).score-report.score;if(v>0)candidates.push({kind:"route",id:r.id,name:r.name+" verified",cost:cost(n.design)-spent,gain:v})}}
  candidates.sort((a,b)=>b.gain-a.gain||a.cost-b.cost||a.id.localeCompare(b.id));
  const maturity=[...new Set(controls.map(c=>c.group))].map(group=>({name:group,total:controls.filter(c=>c.group===group).length,installed:controls.filter(c=>c.group===group&&d.controls.includes(c.id)).length}));
  const exposure={open:routes.filter(r=>!d.controls.includes("seg")||d.routes[r.id]==="open").length,verified:routes.filter(r=>d.controls.includes("seg")&&d.routes[r.id]==="verified").length,denied:routes.filter(r=>d.controls.includes("seg")&&d.routes[r.id]==="denied").length};
  return {report,risk,objectives,recommendation:candidates[0]||null,maturity,exposure,improvement:report.score-base.score,efficiency:spent?Math.round((report.score-base.score)*100/spent)/100:0};
 }
 function exportDesign(d,s){return {version:2,mission:s.id,difficulty:s.difficulty||"standard",design:{controls:[...d.controls],routes:{...d.routes}}}}
 function importDesign(raw){if(!raw||raw.version!==2||!scenarios.some(s=>s.id===raw.mission)||!modes.some(m=>m.id===raw.difficulty)||!raw.design||!Array.isArray(raw.design.controls)||typeof raw.design.routes!=="object"||!raw.design.routes||Array.isArray(raw.design.routes))return null;const s=mission(raw.mission,raw.difficulty);const d=sanitise(raw.design,s);if(raw.design.controls.length!==d.controls.length||raw.design.controls.some(c=>!d.controls.includes(c))||routes.some(r=>raw.design.routes[r.id]!==d.routes[r.id])||Object.keys(raw.design.routes).length!==routes.length)return null;return {scenario:s,design:d}}
 return {controls,zones,routes,threats,scenarios,findScenario,empty,cost,sanitise,change,evaluate,label,modes,mode,mission,key,presets,verifyRoutes,blueprint,evaluateOne,insights,exportDesign,importDesign,required};

})();
if(typeof module !== "undefined")module.exports=ZeroTrust;
