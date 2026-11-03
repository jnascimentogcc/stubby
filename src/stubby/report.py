"""Self-contained HTML report for an OpenVEX document written by ``stubby scan``."""

from __future__ import annotations

import json

from .scan import REASONS

TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Stubby – VEX report</title>
<style>
:root{--bg:#fff;--fg:#1c2024;--mut:#667;--line:#dde1e6;--card:#f6f7f9;--aff:#c62828;--ina:#b26a00;--not:#2e7d32;--link:#1a56c4}
@media(prefers-color-scheme:dark){:root{--bg:#14171a;--fg:#e6e8eb;--mut:#9aa3ad;--line:#2b3138;--card:#1c2025;--aff:#ef6b6b;--ina:#e0a23c;--not:#5fbf6a;--link:#7ab0ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px}h1{margin:0 0 4px;font-size:22px}.sub{color:var(--mut);margin-bottom:16px;overflow-wrap:anywhere}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 16px;min-width:130px;cursor:pointer}
.card.on{outline:2px solid var(--fg)}.card b{display:block;font-size:24px}.aff b{color:var(--aff)}.ina b{color:var(--ina)}.not b{color:var(--not)}
.row{border:1px solid var(--line);border-radius:8px;margin-bottom:8px;padding:10px 14px}.top{display:flex;gap:10px;flex-wrap:wrap;align-items:baseline}
.badge{font-size:12px;font-weight:600;padding:2px 8px;border-radius:99px;border:1px solid currentColor}.badge.affected{color:var(--aff)}.badge.under_investigation{color:var(--ina)}.badge.not_affected{color:var(--not)}
.chips{margin-top:6px;display:flex;gap:6px;flex-wrap:wrap}.chip{font-size:12px;padding:1px 8px;border-radius:99px;background:var(--card);border:1px solid var(--line);color:var(--mut)}
.pkg{font-weight:600}.mut{color:var(--mut);font-size:13px}.title{margin-top:4px;font-weight:500}.notes{margin-top:6px}.just{margin-top:6px;font-size:13px}
a{color:var(--link)}code{background:var(--card);padding:1px 5px;border-radius:4px;font-size:13px}
details{margin-top:6px}summary{cursor:pointer;color:var(--mut);font-size:13px}
.bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}.bar select{padding:8px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font:inherit;max-width:100%}
#q{flex:1;min-width:220px;padding:8px 12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font:inherit}
</style></head><body><main>
<h1>Stubby – VEX report</h1><div class="sub" id="meta"></div>
<div class="cards" id="cards"></div>
<div class="bar"><input id="q" type="search" placeholder="Filter by package, CVE or text..."><select id="r" title="Why it is inconclusive"></select></div>
<div id="list"></div>
</main><script>
let DATA=__DATA__, REASONS=__REASONS__, filter=null, query="", reason="";
const L={affected:["Affected","aff"],under_investigation:["Inconclusive","ina"],not_affected:["Not affected","not"]};
const dec=s=>{try{return decodeURIComponent(s)}catch(e){return s}};
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const safe=u=>/^https:\/\//.test(u||"")?u:null;
function link(id){
  const u=id.startsWith("CVE-")?"https://nvd.nist.gov/vuln/detail/"+id:id.startsWith("GHSA-")?"https://github.com/advisories/"+id:"https://osv.dev/vulnerability/"+id;
  return `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(id)}</a>`;
}
function render(){
  const st=DATA.statements||[], c={};st.forEach(s=>c[s.status]=(c[s.status]||0)+1);
  document.getElementById("meta").textContent=`${st[0]?.products?.[0]?.["@id"]||""} · ${DATA.timestamp} · ${DATA.role}`;
  document.getElementById("cards").innerHTML=Object.entries(L).map(([k,[n,cl]])=>`<div class="card ${cl} ${filter===k?"on":""}" data-k="${k}"><b>${c[k]||0}</b>${n}</div>`).join("");
  document.querySelectorAll(".card").forEach(e=>e.onclick=()=>{filter=filter===e.dataset.k?null:e.dataset.k;render()});
  const rc={};st.forEach(s=>(s["x-stubby-reasons"]||[]).forEach(r=>rc[r]=(rc[r]||0)+1));
  const sel=document.getElementById("r"), keys=Object.keys(rc).sort((a,b)=>rc[b]-rc[a]);
  sel.style.display=keys.length?"":"none";
  sel.innerHTML=`<option value="">All reasons</option>`+keys.map(k=>`<option value="${esc(k)}" ${k===reason?"selected":""}>${esc(REASONS[k]||k)} (${rc[k]})</option>`).join("");
  const rows=st.filter(s=>!filter||s.status===filter)
    .filter(s=>!reason||(s["x-stubby-reasons"]||[]).includes(reason))
    .filter(s=>!query||JSON.stringify(s).toLowerCase().includes(query))
    .sort((a,b)=>(a.status==="under_investigation")-(b.status==="under_investigation"));
  document.getElementById("list").innerHTML=rows.map(s=>{
    const sub=(s.products||[]).flatMap(p=>(p.subcomponents||[]).map(x=>x["@id"]));
    const v=s.vulnerability||{}, ids=[v.name,...(v.aliases||[])].filter(Boolean);
    const desc=v.description||"";
    const explicit=safe(v["@id"]);
    const first=explicit&&ids.length?`<a href="${esc(explicit)}" target="_blank" rel="noopener noreferrer">${esc(ids[0])}</a>`:link(ids[0]||"");
    return `<div class="row"><div class="top"><span class="badge ${s.status}">${(L[s.status]||[s.status])[0]}</span>
      <span class="pkg">${esc(dec(sub.join(", ")).replace(/^pkg:[a-z]+\//,"").replace(/, pkg:[a-z]+\//g,", "))}</span>
      ${first}<span class="mut">${ids.slice(1).map(link).join(", ")}</span></div>
      ${desc?`<div class="title">${esc(desc)}</div>`:""}
      <div class="notes">${esc(s.status_notes||s.impact_statement||"")}</div>
      ${(s["x-stubby-reasons"]||[]).length?`<div class="chips">${s["x-stubby-reasons"].map(r=>`<span class="chip">${esc(REASONS[r]||r)}</span>`).join("")}</div>`:""}
      ${s.justification?`<div class="just mut">Justification: <code>${esc(s.justification)}</code></div>`:""}</div>`}).join("")||"<p class=mut>No findings.</p>";
}
document.getElementById("r").onchange=e=>{reason=e.target.value;render()};
document.getElementById("q").oninput=e=>{query=e.target.value.toLowerCase();render()};
render();
</script></body></html>
"""


def render_report(vex: dict) -> str:
    """Return a standalone HTML page for ``vex`` (no network, no external assets)."""
    data = json.dumps(vex).replace("</", "<\\/")
    return TEMPLATE.replace("__REASONS__", json.dumps(REASONS)).replace("__DATA__", data)
