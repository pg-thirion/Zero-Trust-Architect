(function app(){
 const E=ZeroTrust,$=id=>document.getElementById(id);
 const KEY="zta-v1";
 let saved={};try{const v=JSON.parse(localStorage.getItem(KEY)||"{}");if(v&&typeof v==="object")saved=v}catch{}
 let scenario=E.findScenario(saved.current),design=E.sanitise(saved.designs?.[scenario.id],scenario),report=null;
 let best={};for(const s of E.scenarios){const n=saved.best?.[s.id];if(Number.isInteger(n)&&n>=0&&n<=100)best[s.id]=n}
 let designs={};for(const s of E.scenarios)designs[s.id]=E.sanitise(saved.designs?.[s.id],s);
 let runs=0;let dirty=false;
 const fmt=n=>"$"+n+"k";
 const icons={staff:"M8 11a4 4 0 1 0 8 0a4 4 0 1 0 -8 0 M4 21v-2a4 4 0 0 1 4-4h8a4 4 0 0 1 4 4v2",vendor:"M3 7h18v14H3z M8 7V3h8v4 M3 12h18",app:"M3 4h18v7H3z M3 14h18v7H3z M6 7h2 M6 17h2",data:"M3 6c0-5 18-5 18 0s-18 5-18 0 M3 6v12c0 5 18 5 18 0V6 M3 12c0 5 18 5 18 0",admin:"M12 2l8 4v6c0 5-4 8-8 10-4-2-8-5-8-10V6z M9 12l2 2 4-4",backup:"M3 5h18v15H3z M3 10h18 M10 14h4"};
 function save(){designs[scenario.id]=design;try{localStorage.setItem(KEY,JSON.stringify({current:scenario.id,designs,best}))}catch{}}
 function notice(msg){$("notice").textContent=msg}
 function setScenario(id){save();scenario=E.findScenario(id);design=E.sanitise(designs[scenario.id],scenario);report=null;dirty=false;runs=0;save();render();notice("Mission loaded. Configure your defences.")}
 function edit(kind,id,value){const next=E.change(design,scenario,kind,id,value);if(!next.ok){notice(next.reason);render();return}design=next.design;if(report){report=null;dirty=true}save();render();notice(kind==="control"?"Security investment updated.":"Network policy updated.")}
 function renderMission(){
  $("mission-select").innerHTML=E.scenarios.map((s,i)=>`<button class="mission ${s.id===scenario.id?"active":""}" data-mission="${s.id}" aria-pressed="${s.id===scenario.id}"><span class="mission-num">0${i+1}</span><span><strong>${s.name}</strong><small>${s.type} · ${fmt(s.budget)}</small></span><span class="mission-best">${best[s.id]!==undefined?best[s.id]+"/100":"○"}</span></button>`).join("");
  $("mission-name").textContent=scenario.name;$("mission-desc").textContent=scenario.description;
  $("threat-count").textContent=scenario.threats.length+" incident scenarios";
  $("partner-note").textContent=scenario.partner?"Partner access is business-critical.":"Partner access is optional.";
 }
 function renderBudget(){const spent=E.cost(design),remaining=scenario.budget-spent,percent=100*spent/scenario.budget;
  $("budget").textContent=fmt(remaining);$("spent").textContent=fmt(spent)+" / "+fmt(scenario.budget);
  $("budget-meter").value=spent;$("budget-meter").max=scenario.budget;$("budget-meter").classList.toggle("low",remaining<12);
  $("controls-count").textContent=design.controls.length+" / "+E.controls.length;
  $("policy-count").textContent=E.routes.filter(r=>design.routes[r.id]==="verified").length+" / "+E.routes.length;
  $("best").textContent=best[scenario.id]===undefined?"—":best[scenario.id]+"/100";
 }
 function renderControls(){
  const groups=[...new Set(E.controls.map(c=>c.group))],left=scenario.budget-E.cost(design);
  $("control-list").innerHTML=groups.map(group=>`<section class="control-group"><h3>${group}</h3><div class="control-grid">${E.controls.filter(c=>c.group===group).map(c=>{const on=design.controls.includes(c.id),unaffordable=!on&&c.cost>left;return `<button type="button" id="c-${c.id}" class="control ${on?"selected":""}" data-control="${c.id}" aria-pressed="${on}" ${unaffordable?"aria-disabled=\"true\"":""}><span class="control-check" aria-hidden="true">${on?"✓":"+"}</span><span class="control-copy"><strong>${c.name}</strong><small>${c.desc}</small></span><span class="cost">${fmt(c.cost)}</span></button>`}).join("")}</div></section>`).join("");
 }
 function renderMap(){
  const coords={staff:[88,65],vendor:[88,225],app:[312,65],data:[536,65],admin:[312,225],backup:[536,225]};
  const seg=design.controls.includes("seg");
  $("seg-status").textContent=seg?"Enforced":"Advisory only";$("seg-status").className="pill "+(seg?"good":"warn");
  const edges=E.routes.map(r=>{const [x1,y1]=coords[r.from],[x2,y2]=coords[r.to],p=design.routes[r.id],state=seg?p:"open";return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" class="edge ${state}" /><circle cx="${(x1+x2)/2}" cy="${(y1+y2)/2}" r="4" class="edge-dot ${state}"/>`}).join("");
  const nodes=E.zones.map(([id,name,desc])=>{const [x,y]=coords[id];return `<g transform="translate(${x-77} ${y-35})"><rect width="154" height="70" rx="10" class="node-box"/><g transform="translate(11 17)" fill="none" stroke="#6de2c5" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="${icons[id]}"/></g><text x="43" y="27" class="node-name">${name}</text><text x="12" y="53" class="node-desc">${desc}</text></g>`}).join("");
  $("network-svg").innerHTML=`<title>Fictional network topology</title><desc>Six network zones connected by configurable access routes. Open routes are amber, verified routes green and denied routes dashed red. Without microsegmentation all routes remain open.</desc>${edges}${nodes}`;
  $("route-list").innerHTML=E.routes.map(r=>{const required=r.required||(r.id==="vendor-app"&&scenario.partner),current=design.routes[r.id];return `<div class="route"><div><label for="r-${r.id}">${r.name}</label><small>${required?"Required":"Optional"} · ${seg?current==="open"?"Unrestricted":current==="verified"?"Verified access":"Denied":"Not enforced"}</small></div><select id="r-${r.id}" data-route="${r.id}" aria-label="${r.name} policy"><option value="open" ${current==="open"?"selected":""}>Open · $0k</option><option value="verified" ${current==="verified"?"selected":""}>Verified · $4k</option><option value="denied" ${current==="denied"?"selected":""}>Denied · $0k</option></select></div>`}).join("");
  $("dependencies").innerHTML=`<span class="${seg?"ok":"muted"}">${seg?"✓":"○"} Microsegmentation ${seg?"active":"required to enforce routes"}</span><span class="${design.controls.includes("logs")?"ok":"muted"}">${design.controls.includes("logs")?"✓":"○"} Logging ${design.controls.includes("logs")?"active":"required for incident response"}</span>`;
 }
 function renderReport(){
  const area=$("report");
  if(!report){area.innerHTML=`<div class="empty-report"><div class="empty-icon">◎</div><strong>${dirty?"Architecture changed":"Awaiting simulation"}</strong><p>${dirty?"Run the threat suite again to assess the updated design.":"Configure security controls and network policies, then run the threat suite to see how your architecture performs."}</p></div>`;$("export").disabled=true;return}
  const r=report;
  const grade=r.score>=90?"Exceptional":r.score>=75?"Resilient":r.score>=55?"Developing":"High risk";
  const summary=["Prevented","Contained","Recovered","Compromised"].map(status=>`<span class="summary-item ${status.toLowerCase()}"><strong>${r.results.filter(t=>t.status===status).length}</strong> ${status}</span>`).join("");
  area.innerHTML=`<div class="score-grid"><div class="score-main"><span>ARCHITECTURE SCORE</span><strong>${r.score}<small>/100</small></strong><span>${grade}</span></div><div class="score-side"><div><span>Security</span><strong>${r.security}%</strong><progress class="mini-track" max="100" value="${r.security}" aria-label="Security score"></progress></div><div><span>Business availability</span><strong>${r.availability}%</strong><progress class="mini-track" max="100" value="${r.availability}" aria-label="Business availability"></progress></div></div></div><div class="result-summary">${summary}</div>${r.broken.length?`<div class="warning">Disrupted services: ${r.broken.join(", ")}. Restore required routes with verified access.</div>`:"<div class=\"success-note\">All required business routes remain available.</div>"}<div class="incident-list">${r.results.map(t=>`<details class="incident"><summary><span class="incident-dot ${t.status.toLowerCase()}"></span><span><strong>${t.name}</strong><small>${t.entry} · impact ${t.weight}</small></span><span class="result-tag ${t.status.toLowerCase()}">${t.status}</span></summary><div class="incident-detail"><p>${t.matched.length?"Effective controls: "+t.matched.map(E.label).join(", "):"Suggested prevention: "+t.prevent[0].map(E.label).join(" + ")}</p><p>${t.lesson}</p></div></details>`).join("")}</div><p class="fine">Run ${runs} · ${fmt(r.spent)} invested · Score weights: 75% security, 25% availability.</p>`;
  $("export").disabled=false;
 }
 function render(){renderMission();renderBudget();renderControls();renderMap();renderReport()}
 function run(){report=E.evaluate(design,scenario);dirty=false;runs++;best[scenario.id]=Math.max(best[scenario.id]??0,report.score);save();render();notice("Simulation complete. "+report.score+" out of 100. Review the incident results.");$("report-title").focus();$("report-title").scrollIntoView({behavior:matchMedia("(prefers-reduced-motion: reduce)").matches?"auto":"smooth",block:"nearest"})}
 function exportReport(){if(!report)return;const r=report;const lines=["ZERO TRUST ARCHITECT | SIMULATION REPORT",scenario.name,`Score: ${r.score}/100 | Security: ${r.security}% | Availability: ${r.availability}%`,`Budget: ${fmt(r.spent)} / ${fmt(scenario.budget)}`,"","SECURITY CONTROLS",...E.controls.filter(c=>design.controls.includes(c.id)).map(c=>c.name),"","NETWORK POLICIES",...E.routes.map(x=>x.name+": "+design.routes[x.id]+(design.controls.includes("seg")?"":" (advisory)")),"","THREAT RESULTS",...r.results.flatMap(t=>[t.name+": "+t.status,t.lesson]),"","Educational simulation only. Not a real network security assessment."];const u=URL.createObjectURL(new Blob([lines.join("\n")],{type:"text/plain"}));const a=document.createElement("a");a.href=u;a.download="zero-trust-"+scenario.id+"-report.txt";a.click();setTimeout(()=>URL.revokeObjectURL(u),1000)}
 document.addEventListener("click",e=>{const target=e.target.closest("button");if(!target)return;if(target.dataset.mission){setScenario(target.dataset.mission);document.querySelector(`[data-mission="${scenario.id}"]`).focus()}else if(target.dataset.control){const id=target.dataset.control;edit("control",id);$("c-"+id).focus()}});
 document.addEventListener("change",e=>{if(e.target.dataset.route){const id=e.target.dataset.route;edit("route",id,e.target.value);$("r-"+id).focus()}});
 $("run").addEventListener("click",run);
 $("export").addEventListener("click",exportReport);
 $("reset").addEventListener("click",()=>{if(!confirm("Reset this mission's current architecture? Your best score will be retained."))return;design=E.empty();report=null;dirty=false;runs=0;save();render();notice("Architecture reset.")});
 render();
 $("boot-message").hidden=true;
})();
