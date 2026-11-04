"""Self-contained HTML report for an OpenVEX document written by ``stubby scan``."""

from __future__ import annotations

import json

from .scan import REASONS

TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Stubby – VEX report</title>
<style>
/* Design tokens: docs/ui-spec.md section 3.2 */
:root{color-scheme:light;
--bg:#ece6da;--bg-2:#e4ddcf;--surface:#f8f5ee;--surface-2:#f1ece2;--surface-muted:#caceb5;
--border:rgba(47,53,67,.14);--border-2:rgba(47,53,67,.24);--border-strong:rgba(47,53,67,.36);
--text:#1f2532;--text-2:#4e615b;--text-3:rgba(31,37,50,.58);--text-inverse:#ece6da;
--accent:#4e615b;--accent-hover:#43544f;--accent-soft:rgba(78,97,91,.12);--accent-soft-2:rgba(78,97,91,.18);
--success:#4e615b;--success-bg:rgba(78,97,91,.12);--success-border:rgba(78,97,91,.28);
--warning:#b7791f;--warning-bg:rgba(183,121,31,.13);--warning-border:rgba(183,121,31,.30);
--danger:#b94a3a;--danger-bg:rgba(185,74,58,.12);--danger-border:rgba(185,74,58,.30);
--info:#3f647c;--info-bg:rgba(63,100,124,.12);--info-border:rgba(63,100,124,.30);
--shadow:0 1px 3px rgba(31,37,50,.08),0 1px 2px rgba(31,37,50,.05);--sans:"DM Sans","Inter",system-ui,sans-serif;--mono:"IBM Plex Mono","SFMono-Regular",Consolas,monospace;
--space-1:4px;--space-2:8px;--space-3:12px;--space-4:16px;--space-5:20px;--space-6:24px;--space-8:32px;
--radius-sm:4px;--radius:6px;--radius-lg:10px;--content-max:1360px;--transition:180ms ease;}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;
--bg:#1f2532;--bg-2:#252c3a;--surface:#2f3543;--surface-2:#363d4d;--surface-muted:rgba(202,206,181,.12);
--border:rgba(236,230,218,.12);--border-2:rgba(236,230,218,.20);--border-strong:rgba(236,230,218,.34);
--text:#ece6da;--text-2:#caceb5;--text-3:rgba(236,230,218,.58);--text-inverse:#1f2532;
--accent:#caceb5;--accent-hover:#d8dbc7;--accent-soft:rgba(202,206,181,.13);--accent-soft-2:rgba(202,206,181,.20);
--success:#caceb5;--success-bg:rgba(202,206,181,.13);--success-border:rgba(202,206,181,.30);
--warning:#d49a3a;--warning-bg:rgba(212,154,58,.14);--warning-border:rgba(212,154,58,.32);
--danger:#e06a5b;--danger-bg:rgba(224,106,91,.14);--danger-border:rgba(224,106,91,.34);
--info:#8eaec1;--info-bg:rgba(142,174,193,.14);--info-border:rgba(142,174,193,.34);
--shadow:0 1px 3px rgba(0,0,0,.32),0 1px 2px rgba(0,0,0,.22);}}
[data-theme="dark"]{color-scheme:dark;
--bg:#1f2532;--bg-2:#252c3a;--surface:#2f3543;--surface-2:#363d4d;--surface-muted:rgba(202,206,181,.12);
--border:rgba(236,230,218,.12);--border-2:rgba(236,230,218,.20);--border-strong:rgba(236,230,218,.34);
--text:#ece6da;--text-2:#caceb5;--text-3:rgba(236,230,218,.58);--text-inverse:#1f2532;
--accent:#caceb5;--accent-hover:#d8dbc7;--accent-soft:rgba(202,206,181,.13);--accent-soft-2:rgba(202,206,181,.20);
--success:#caceb5;--success-bg:rgba(202,206,181,.13);--success-border:rgba(202,206,181,.30);
--warning:#d49a3a;--warning-bg:rgba(212,154,58,.14);--warning-border:rgba(212,154,58,.32);
--danger:#e06a5b;--danger-bg:rgba(224,106,91,.14);--danger-border:rgba(224,106,91,.34);
--info:#8eaec1;--info-bg:rgba(142,174,193,.14);--info-border:rgba(142,174,193,.34);
--shadow:0 1px 3px rgba(0,0,0,.32),0 1px 2px rgba(0,0,0,.22);}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font:14px/1.55 var(--sans);-webkit-font-smoothing:antialiased}
main{max-width:var(--content-max);margin:0 auto;padding:var(--space-6) var(--space-4)}
@media(min-width:640px){main{padding-inline:var(--space-6)}}
header{display:flex;gap:var(--space-4);flex-wrap:wrap;align-items:flex-start;justify-content:space-between;margin-bottom:var(--space-4)}
h1{margin:0 0 var(--space-1);font-size:22px;line-height:1.3}
.sub{color:var(--text-3);overflow-wrap:anywhere;font-family:var(--mono);font-size:12px}
button,select,input{font:inherit;color:var(--text)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.btn{min-height:44px;padding:0 var(--space-4);border:1px solid var(--border-2);border-radius:var(--radius);background:transparent;cursor:pointer;transition:background var(--transition)}
.btn:hover{background:var(--accent-soft)}.btn:active{background:var(--accent-soft-2)}
.cards{display:flex;gap:var(--space-3);flex-wrap:wrap;margin-bottom:var(--space-4)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);box-shadow:var(--shadow);padding:var(--space-3) var(--space-4);min-width:140px;min-height:44px;text-align:left;cursor:pointer;transition:background var(--transition)}
.card:hover{background:var(--surface-2)}.card[aria-pressed=true]{border-color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent)}
.card b{display:block;font:600 24px/1.2 var(--mono)}.aff b{color:var(--danger)}.ina b{color:var(--warning)}.not b{color:var(--success)}
.row{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);margin-bottom:var(--space-2);padding:var(--space-3) var(--space-4)}
.top{display:flex;gap:var(--space-3);flex-wrap:wrap;align-items:baseline}
.badge{font-size:12px;font-weight:600;padding:2px var(--space-2);border-radius:var(--radius-sm);border:1px solid var(--border-2);background:var(--surface-2)}
.badge.affected{color:var(--danger);background:var(--danger-bg);border-color:var(--danger-border)}
.badge.under_investigation{color:var(--warning);background:var(--warning-bg);border-color:var(--warning-border)}
.badge.not_affected{color:var(--success);background:var(--success-bg);border-color:var(--success-border)}
.chips{margin-top:var(--space-2);display:flex;gap:var(--space-2);flex-wrap:wrap}
.chip{font-size:12px;padding:1px var(--space-2);border-radius:var(--radius-sm);background:var(--surface-muted);border:1px solid var(--border);color:var(--text-2)}
.pkg{font:600 13px var(--mono);overflow-wrap:anywhere}.mut{color:var(--text-3);font-family:var(--mono);font-size:12px}
.title{margin-top:var(--space-1);font-weight:500}.notes{margin-top:var(--space-2)}.just{margin-top:var(--space-2)}
a{color:var(--info)}a:hover{color:var(--accent-hover)}
code{background:var(--surface-2);padding:1px 5px;border-radius:var(--radius-sm);font:12px var(--mono)}
.bar{display:flex;gap:var(--space-2);flex-wrap:wrap;margin-bottom:var(--space-3)}
.bar select,#q{min-height:44px;padding:0 var(--space-3);border:1px solid var(--border-2);border-radius:var(--radius);background:var(--surface);max-width:100%}
#q{flex:1;min-width:220px}
.empty{padding:var(--space-8) var(--space-4);text-align:center;color:var(--text-3)}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}
</style></head><body><main>
<header><div><h1>Stubby – VEX report</h1><div class="sub" id="meta"></div></div><button class="btn" id="theme" type="button" aria-label="Switch between light and dark theme">Theme</button></header>
<div class="cards" id="cards"></div>
<div class="bar"><input id="q" type="search" aria-label="Filter findings" placeholder="Filter by package, CVE or text..."><select id="sc" title="Scope" aria-label="Scope"><option value="">Runtime and development</option><option value="runtime">Runtime only</option><option value="dev">Development only</option></select><select id="r" title="Why it is inconclusive" aria-label="Why it is inconclusive"></select></div>
<div id="list"></div>
</main><script>
let DATA=__DATA__, REASONS=__REASONS__, filter=null, query="", reason="", scope="";
const isDev=s=>s["x-stubby-scope"]==="development"||/only required by devDependencies/.test(s.status_notes||"");
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
  const nd=st.filter(isDev).length;
  document.getElementById("meta").textContent=`${st[0]?.products?.[0]?.["@id"]||""} · ${DATA.timestamp} · ${DATA.role}`+(nd?` · ${nd} of ${st.length} findings only affect development dependencies`:"");
  document.getElementById("cards").innerHTML=Object.entries(L).map(([k,[n,cl]])=>`<button type="button" class="card ${cl}" data-k="${k}" aria-pressed="${filter===k}"><b>${c[k]||0}</b>${n}</button>`).join("");
  document.querySelectorAll(".card").forEach(e=>e.onclick=()=>{filter=filter===e.dataset.k?null:e.dataset.k;render()});
  const rc={};st.forEach(s=>(s["x-stubby-reasons"]||[]).forEach(r=>rc[r]=(rc[r]||0)+1));
  const sel=document.getElementById("r"), keys=Object.keys(rc).sort((a,b)=>rc[b]-rc[a]);
  sel.style.display=keys.length?"":"none";
  sel.innerHTML=`<option value="">All reasons</option>`+keys.map(k=>`<option value="${esc(k)}" ${k===reason?"selected":""}>${esc(REASONS[k]||k)} (${rc[k]})</option>`).join("");
  const rows=st.filter(s=>!filter||s.status===filter)
    .filter(s=>!reason||(s["x-stubby-reasons"]||[]).includes(reason))
    .filter(s=>!scope||(scope==="dev")===isDev(s))
    .filter(s=>!query||JSON.stringify(s).toLowerCase().includes(query))
    .sort((a,b)=>(a.status==="under_investigation")-(b.status==="under_investigation")||isDev(a)-isDev(b));
  document.getElementById("list").innerHTML=rows.map(s=>{
    const sub=(s.products||[]).flatMap(p=>(p.subcomponents||[]).map(x=>x["@id"]));
    const v=s.vulnerability||{}, ids=[v.name,...(v.aliases||[])].filter(Boolean);
    const desc=v.description||"";
    const explicit=safe(v["@id"]);
    const first=explicit&&ids.length?`<a href="${esc(explicit)}" target="_blank" rel="noopener noreferrer">${esc(ids[0])}</a>`:link(ids[0]||"");
    return `<div class="row"><div class="top"><span class="badge ${s.status}">${(L[s.status]||[s.status])[0]}</span>${isDev(s)?`<span class="chip" title="Not part of the shipped runtime">dev</span>`:""}
      <span class="pkg">${esc(dec(sub.join(", ")).replace(/^pkg:[a-z]+\//,"").replace(/, pkg:[a-z]+\//g,", "))}</span>
      ${first}<span class="mut">${ids.slice(1).map(link).join(", ")}</span></div>
      ${desc?`<div class="title">${esc(desc)}</div>`:""}
      <div class="notes">${esc(s.status_notes||s.impact_statement||"")}</div>
      ${(s["x-stubby-reasons"]||[]).length?`<div class="chips">${s["x-stubby-reasons"].map(r=>`<span class="chip">${esc(REASONS[r]||r)}</span>`).join("")}</div>`:""}
      ${s.justification?`<div class="just mut">Justification: <code>${esc(s.justification)}</code></div>`:""}</div>`}).join("")||"<p class=empty>No findings match the current filters.</p>";
}
document.getElementById("theme").onclick=()=>{
  const root=document.documentElement, dark=root.dataset.theme?root.dataset.theme==="dark":matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme=dark?"light":"dark";
};
document.getElementById("sc").onchange=e=>{scope=e.target.value;render()};
document.getElementById("r").onchange=e=>{reason=e.target.value;render()};
document.getElementById("q").oninput=e=>{query=e.target.value.toLowerCase();render()};
render();
</script></body></html>
"""


def render_report(vex: dict) -> str:
    """Return a standalone HTML page for ``vex`` (no network, no external assets)."""
    data = json.dumps(vex).replace("</", "<\\/")
    return TEMPLATE.replace("__REASONS__", json.dumps(REASONS)).replace("__DATA__", data)
