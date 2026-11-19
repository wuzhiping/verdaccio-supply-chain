#!/usr/bin/env python3
"""Read-only HTTP publisher for the generated reports; Python standard library only."""
import os, re, hmac, json, logging, threading
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote

from scan_control import CONTROL, LOCK
import review_store

log = logging.getLogger("supply-chain.http")
RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

BIND = os.getenv("REPORT_HTTP_BIND", "0.0.0.0")
PORT = int(os.getenv("REPORT_HTTP_PORT", "8080"))
TOKEN = os.getenv("REPORT_TOKEN", "").strip()
ROOT = Path(os.getenv("REPORT_DIR", "/reports"))
COOKIE = "sbom_token"
HEALTH_PATH = "/healthz"
SCAN_PATH = "/api/scan"
SCAN_STATUS_PATHS = (SCAN_PATH, SCAN_PATH + "/status")
PROGRESS_PATH = "/progress"
RISK_PATH = "/risk"
REVIEWED_PATH = "/reviewed"
REVIEW_API_KEY = os.getenv("REVIEW_API_KEY", "123456").strip()
RISK_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
YEAR = datetime.now(timezone.utc).year
REVIEWS = review_store.ReviewStore(str(ROOT / "risks"))
PAGE_SIZE = max(20, int(os.getenv("REPORT_PAGE_SIZE", "100")))
RETRY_AFTER = os.getenv("SCAN_RETRY_AFTER_SECONDS", "10")

PROGRESS_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Scan progress</title><style>
*{box-sizing:border-box;scrollbar-width:thin;scrollbar-color:rgba(49,95,189,.42) transparent}body{margin:0;background:#f3f5f9;color:#172033;font:14px/1.5 system-ui,sans-serif}

::-webkit-scrollbar{width:3px;height:3px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(49,95,189,.42);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:rgba(49,95,189,.68)}
::-webkit-scrollbar-corner{background:transparent}
header{position:sticky;top:0;z-index:30;background:linear-gradient(100deg,#0e2340 0%,#1a3a6d 58%,#24518f 100%);color:#fff;padding:14px 20px;box-shadow:0 3px 14px rgba(14,35,64,.32);border-bottom:3px solid #3f8fe0;display:flex;justify-content:space-between;align-items:center;gap:18px;flex-wrap:wrap}
.headleft{min-width:0}
.copy{flex:0 0 auto;display:inline-flex;align-items:center;gap:7px;padding:7px 16px;border:1px solid rgba(255,255,255,.32);border-radius:20px;background:rgba(255,255,255,.12);color:#dbe7f7;font-size:12.5px;letter-spacing:.3px;white-space:nowrap}
.copy b{color:#fff;font-weight:700;letter-spacing:.6px}
header h1{margin:0;font-size:21px}header h1 a{color:#fff;text-decoration:none}header h1 a:hover{text-decoration:none;opacity:.92}header p{color:#bcd0ea;margin:4px 0 0;font-size:13px}
main{max-width:920px;margin:22px auto;padding:0 18px}
.card{background:#fff;border:1px solid #e3e8f0;border-radius:11px;padding:16px;margin-bottom:14px}
.bar{height:16px;background:#eef1f5;border-radius:20px;overflow:hidden;margin:8px 0 14px}
.bar>span{display:block;height:100%;width:0;background:linear-gradient(90deg,#315fbd,#5b8def);transition:width .4s}
table{border-collapse:collapse;width:100%}td,th{padding:7px 4px;border-bottom:1px solid #e5e9f0;text-align:left;vertical-align:top}
th{width:150px;color:#526078;font-weight:600}.mono{font-family:ui-monospace,monospace;font-size:12px}
button{padding:9px 16px;border:0;border-radius:8px;background:#315fbd;color:#fff;font-size:14px;cursor:pointer}
button:hover{background:#254a99}a{color:#315fbd}.hint{color:#68758b;font-size:13px}
footer.foot{margin:26px auto 32px;padding:0 18px;display:flex;justify-content:center;align-items:center;gap:16px;flex-wrap:wrap;color:#8794a8;font-size:12px;letter-spacing:.2px}footer.foot b{color:#68758b;font-weight:600}
footer.foot .refresh{display:inline-flex;align-items:center;gap:7px;white-space:nowrap}footer.foot .refresh select{padding:5px 8px;border:1px solid #ccd4e2;border-radius:7px;background:#fff;color:#46536b;font-size:12px}footer.foot .refresh label{color:#68758b}
@media (max-width:640px){main{padding:0 10px;margin:14px auto}header{padding:10px 12px}.copy{font-size:10.5px;padding:5px 11px}footer.foot{flex-direction:column;gap:10px}}
</style></head><body><header><div class="headleft"><h1><a data-home="1" href="">SBOM: Supply Chain Security</a> · scan progress</h1><p id="state">loading…</p></div><div class="copy">Copyright &copy; 2026 <b>AIFE in FEIT</b></div></header>
<main><section class="card"><div class="bar"><span id="fill"></span></div>
<table><tr><th>Current scan</th><td id="cur">-</td></tr>
<tr><th>Phase</th><td id="phase">-</td></tr>
<tr><th>Progress</th><td id="pct">-</td></tr>
<tr><th>Processed</th><td id="count" class="mono">-</td></tr>
<tr><th>Detail</th><td id="msg">-</td></tr>
<tr><th>Elapsed</th><td id="elapsed">-</td></tr>
<tr><th>Previous scan</th><td id="last">-</td></tr>
<tr><th>Updated</th><td id="updated" class="mono">-</td></tr></table></section>
<section class="card"><button id="go">Run scan now</button> <span class="hint" id="gomsg"></span>
<p><a id="report" data-rel="." href="./?q=&amp;scope=relevant&amp;eco=&amp;risk=CRITICAL">Open latest report</a></p></section></main>
<footer class="foot"><span>Developed by <b>Ateam+</b></span><span class="refresh"><label for="refresh">auto refresh</label>
<select id="refresh" title="How often the page reloads itself">
<option value="60">1 min</option><option value="300">5 min</option>
<option value="1800" selected>30 min</option><option value="3600">60 min</option></select></span></footer>
<script>
const $=id=>document.getElementById(id);
// resolve relative to the current path so a reverse proxy path prefix keeps working
function appDir(){
  var p=location.pathname;
  if(p.charAt(p.length-1)==='/')return p;
  var last=p.slice(p.lastIndexOf('/')+1);
  if(last===''||last==='progress'||last==='index.html')return p.slice(0,p.lastIndexOf('/')+1);
  return p+'/';
}
const dir=appDir();
const base=new URL(dir,location.href).href;
const api=new URL(dir+'api/scan',location.href).href;
document.querySelectorAll('a[data-home]').forEach(function(a){a.href=dir;});
document.querySelectorAll('a[data-rel]').forEach(function(a){a.href=new URL(dir+a.getAttribute('data-rel'),location.href).href;});
const token=new URLSearchParams(location.search).get('token');
const withToken=u=>token?u+(u.includes('?')?'&':'?')+'token='+encodeURIComponent(token):u;
$('report').href=base+'?q=&scope=relevant&eco=&risk=CRITICAL';
async function poll(){
 try{
  const d=await (await fetch(withToken(api),{headers:{Accept:'application/json'}})).json();
  const p=d.progress||{};
  $('state').textContent=(d.running?'SCAN RUNNING':'IDLE')+' · phase='+d.phase;
  $('phase').textContent=p.phase||'-';
  const known=(p.percent!==null&&p.percent!==undefined);
  $('fill').style.width=(known?p.percent:0)+'%';
  $('pct').textContent=known?p.percent+'%':'—';
  $('count').textContent=(p.current||0)+(p.total?' / '+p.total:'');
  $('msg').textContent=p.message||'-';
  $('elapsed').textContent=(d.elapsed_seconds===null||d.elapsed_seconds===undefined)?'-':d.elapsed_seconds+' s';
  $('updated').textContent=p.updated_at||'-';
  const s=d.last_summary;
  $('last').textContent=s?('packages '+s.unique_packages+' · versions '+s.package_versions+
    ' · findings '+s.vulnerability_findings+' · '+(s.duration_seconds||0)+'s'):'—';
  $('cur').textContent=d.running?('running · '+(p.phase||'-')+' '+(p.percent===null||p.percent===undefined?'':p.percent+'%')):'idle';
 }catch(e){$('state').textContent='error: '+e}
}
$('go').addEventListener('click',async()=>{
 try{
  const r=await fetch(withToken(api),{method:'POST'});
  if(r.status===202){$('gomsg').textContent='scan scheduled';}
  else if(r.status===429){$('gomsg').textContent='a scan is already running';}
  else{const b=(await r.text()).slice(0,160);$('gomsg').textContent='failed: HTTP '+r.status+' '+(b||'');}
 }catch(e){$('gomsg').textContent='failed: '+e}
 poll();
});
poll();setInterval(poll,2000);
</script></body></html>"""


RISK_HEAD = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SBOM: Supply Chain Security · risk {{level}}</title><style>
*{box-sizing:border-box;scrollbar-width:thin;scrollbar-color:rgba(49,95,189,.42) transparent}body{margin:0;background:#f3f5f9;color:#172033;font:14px/1.5 system-ui,sans-serif}

::-webkit-scrollbar{width:3px;height:3px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(49,95,189,.42);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:rgba(49,95,189,.68)}
::-webkit-scrollbar-corner{background:transparent}
header{position:sticky;top:0;z-index:30;background:linear-gradient(100deg,#0e2340 0%,#1a3a6d 58%,#24518f 100%);color:#fff;padding:14px max(20px,calc((100vw - 1450px)/2));box-shadow:0 3px 14px rgba(14,35,64,.32);border-bottom:3px solid #3f8fe0;display:flex;justify-content:space-between;align-items:center;gap:18px;flex-wrap:wrap}
.headleft{min-width:0}
.copy{flex:0 0 auto;display:inline-flex;align-items:center;gap:7px;padding:7px 16px;border:1px solid rgba(255,255,255,.32);border-radius:20px;background:rgba(255,255,255,.12);color:#dbe7f7;font-size:12.5px;letter-spacing:.3px;white-space:nowrap}
.copy b{color:#fff;font-weight:700;letter-spacing:.6px}
header h1{margin:0;font-size:22px}header h1 a{color:#fff;text-decoration:none}header h1 a:hover{text-decoration:none;opacity:.92}header p{color:#bcd0ea;margin:4px 0 0;font-size:13px}
main{max-width:1450px;margin:22px auto;padding:0 18px}.panel{background:#fff;border:1px solid #e3e8f0;border-radius:11px;padding:16px;margin-bottom:14px}
.toolbar{display:flex;gap:10px;margin:12px 0;flex-wrap:wrap;align-items:center}
input[type=text],input[type=password]{padding:9px;border:1px solid #ccd4e2;border-radius:8px}
button{padding:9px 14px;border:1px solid #ccd4e2;border-radius:8px;background:#fff;cursor:pointer}button:hover{background:#eef2f9}
.tablewrap{overflow:auto}table{border-collapse:collapse;width:100%;min-width:900px}td,th{padding:9px;border-bottom:1px solid #e5e9f0;text-align:left;vertical-align:top}th{background:#f8f9fc;color:#526078}
code{font-size:11px;overflow-wrap:anywhere}a{color:#315fbd}.meta{color:#68758b;font-size:12px}
.risk{padding:2px 8px;border-radius:20px;background:#eef1f5;font-size:11px;font-weight:bold}
.tag{display:inline-block;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:bold;vertical-align:middle}
.tag.critical{background:#fdeaea;color:#8d1b2c}.tag.high{background:#fff0e2;color:#8a4a08}
.tag.medium{background:#fff7df;color:#7a5600}.tag.low{background:#e9f7ee;color:#14653a}.tag.unknown{background:#eef1f6;color:#4a566b}
.critical,.high{background:#fdeaea;color:#8d1b2c}.medium{background:#fff7df;color:#7a5600}.low{background:#e9f7ee;color:#14653a}.unknown{background:#eef1f6;color:#4a566b}
.reviewed{opacity:.45}.reviewed td:nth-child(2){text-decoration:line-through}
.checkbox{width:17px;height:17px}.links a{margin-right:12px}
</style></head><body><header><div class="headleft"><h1><a data-home="1" href="">SBOM: Supply Chain Security</a> <span class="tag {{level_class}}">{{level}}</span></h1><p>{{subtitle}}</p></div><div class="copy">Copyright &copy; {{year}} <b>AIFE in FEIT</b></div></header>
<main><section class="panel"><div class="toolbar">
<input id="key" type="password" placeholder="API key for review (saved in this browser)">
<button id="savekey" type="button">Save key</button>
<a href="?show={{show_other}}">show reviewed: {{show_label}}</a>
<span class="meta" id="pager">{{pager}}</span></div>
<div class="tablewrap"><table><thead><tr><th></th><th>Package</th><th>Version</th><th>Advisory</th><th>Severity</th><th>Score</th><th>SHA256</th><th>Relevance</th></tr></thead>
<tbody id="rows">{{rows}}</tbody></table></div>
<div class="toolbar">{{nav}}</div>
<div class="meta links">JSON export: {{exports}}</div></section></main>
<footer class="foot"><span>Developed by <b>Ateam+</b></span><span class="refresh"><label for="refresh">auto refresh</label>
<select id="refresh" title="How often the page reloads itself">
<option value="60">1 min</option><option value="300">5 min</option>
<option value="1800" selected>30 min</option><option value="3600">60 min</option></select></span></footer>

<script>
function appDir(){{
  var p=location.pathname;
  var i=p.lastIndexOf('/risk');
  if(i>=0)return p.slice(0,i+1);
  if(p.charAt(p.length-1)==='/')return p;
  return p+'/';
}}
var DIR=appDir();
document.querySelectorAll('a[data-home]').forEach(function(a){{a.href=DIR;}});
document.querySelectorAll('a[data-rel]').forEach(function(a){{a.href=DIR+a.getAttribute('data-rel');}});
const KEY=localStorage.getItem('sbom_api_key')||'';
document.getElementById('key').value=KEY;
document.getElementById('savekey').addEventListener('click',function(){localStorage.setItem('sbom_api_key',document.getElementById('key').value);});
document.querySelectorAll('#rows input[type=checkbox]').forEach(function(box){
  box.addEventListener('change',async function(){
    const key=decodeURIComponent(box.getAttribute('data-k'));
    const row=box.closest('tr');
    const apiKey=document.getElementById('key').value;
    if(!apiKey){{alert('Please enter the API key first');box.checked=!box.checked;return;}}
    try{
      const r=await fetch(DIR+'api/review',{method:'POST',headers:{'Content-Type':'application/json','X-API-Key':apiKey},body:JSON.stringify({key:key,reviewed:box.checked})});
      if(!r.ok){alert('Failed: HTTP '+r.status+' (API key needed)');box.checked=!box.checked;return;}
      row.classList.toggle('reviewed',box.checked);
    }catch(e){alert('Failed: '+e);box.checked=!box.checked;}
  });
});

(function(){{
  // the refresh interval is kept in the browser
  var sel=document.getElementById('refresh');
  if(!sel)return;
  var KEY='sbom_refresh';
  var saved=parseInt(localStorage.getItem(KEY)||'1800',10);
  if(!saved) saved=1800;
  sel.value=String(saved);
  var timer=null;
  function apply(){{
    if(timer)clearInterval(timer);
    timer=setInterval(function(){{location.reload();}},parseInt(sel.value,10)*1000);
  }}
  sel.addEventListener('change',function(){{localStorage.setItem(KEY,sel.value);apply();}});
  apply();
}})();
</script></body></html>"""

RISK_INDEX_HEAD = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SBOM: Supply Chain Security · risks</title><style>__STYLE__</style></head>
<body><header><div class="headleft"><h1><a data-home="1" href="">SBOM: Supply Chain Security</a></h1><p>{{subtitle}}</p></div><div class="copy">Copyright &copy; {{year}} <b>AIFE in FEIT</b></div></header>
<main><section class="cards">{{cards}}</section>
<section class="panel"><h2>Findings per severity level</h2><p class="meta">{{links}}</p>
<div class="meta">JSON export: {{exports}}</div></section></main>
<footer class="foot"><span>Developed by <b>Ateam+</b></span><span class="refresh"><label for="refresh">auto refresh</label>
<select id="refresh" title="How often the page reloads itself">
<option value="60">1 min</option><option value="300">5 min</option>
<option value="1800" selected>30 min</option><option value="3600">60 min</option></select></span></footer>

<script>
(function(){{
function appDir(){{
  var p=location.pathname;
  var i=p.lastIndexOf('/risk');
  if(i>=0)return p.slice(0,i+1);
  if(p.charAt(p.length-1)==='/')return p;
  return p+'/';
}}
  var dir=appDir();
  document.querySelectorAll('a[data-home]').forEach(function(a){{a.href=dir;}});
  document.querySelectorAll('a[data-rel]').forEach(function(a){{a.href=dir+a.getAttribute('data-rel');}});
}})();

(function(){{
  // the refresh interval is kept in the browser
  var sel=document.getElementById('refresh');
  if(!sel)return;
  var KEY='sbom_refresh';
  var saved=parseInt(localStorage.getItem(KEY)||'1800',10);
  if(!saved) saved=1800;
  sel.value=String(saved);
  var timer=null;
  function apply(){{
    if(timer)clearInterval(timer);
    timer=setInterval(function(){{location.reload();}},parseInt(sel.value,10)*1000);
  }}
  sel.addEventListener('change',function(){{localStorage.setItem(KEY,sel.value);apply();}});
  apply();
}})();
</script></body></html>"""

REVIEWED_HEAD = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SBOM: Supply Chain Security · reviewed</title><style>__STYLE__
.reviewed td:nth-child(2){text-decoration:line-through}
</style></head>
<body><header><div class="headleft"><h1><a data-home="1" href="">SBOM: Supply Chain Security</a> <span class="tag unknown">reviewed</span></h1><p>{{subtitle}}</p></div><div class="copy">Copyright &copy; {{year}} <b>AIFE in FEIT</b></div></header>
<main><section class="cards">{{cards}}</section>
<section class="panel"><div class="toolbar">
<input id="key" type="password" placeholder="API key for review (saved in this browser)">
<button id="savekey" type="button">Save key</button>
<a href="?level={{other_level}}">only {{level_label}}</a>
<span class="meta">{{pager}}</span></div>
<div class="tablewrap"><table><thead><tr><th></th><th>Package</th><th>Version</th><th>Advisory</th><th>Severity</th><th>Score</th><th>SHA256</th><th>Relevance</th></tr></thead>
<tbody id="rows">{{rows}}</tbody></table></div>
<div class="toolbar">{{nav}}</div>
<div class="meta links">{{exports}}</div></section></main>
<footer class="foot"><span>Developed by <b>Ateam+</b></span><span class="refresh"><label for="refresh">auto refresh</label>
<select id="refresh" title="How often the page reloads itself">
<option value="60">1 min</option><option value="300">5 min</option>
<option value="1800" selected>30 min</option><option value="3600">60 min</option></select></span></footer>

<script>
function appDir(){{
  var p=location.pathname;
  var i=p.lastIndexOf('/reviewed');
  if(i>=0)return p.slice(0,i+1);
  if(p.charAt(p.length-1)==='/')return p;
  return p+'/';
}}
var DIR=appDir();
document.querySelectorAll('a[data-home]').forEach(function(a){{a.href=DIR;}});
document.querySelectorAll('a[data-rel]').forEach(function(a){{a.href=DIR+a.getAttribute('data-rel');}});
const KEY=localStorage.getItem('sbom_api_key')||'';
document.getElementById('key').value=KEY;
document.getElementById('savekey').addEventListener('click',function(){{localStorage.setItem('sbom_api_key',document.getElementById('key').value);}});
document.querySelectorAll('#rows input[type=checkbox]').forEach(function(box){{
  box.addEventListener('change',async function(){{
    const key=decodeURIComponent(box.getAttribute('data-k'));
    const row=box.closest('tr');
    const apiKey=document.getElementById('key').value;
    if(!apiKey){{alert('Please enter the API key first');box.checked=!box.checked;return;}}
    try{{
      const r=await fetch(DIR+'api/review',{{method:'POST',headers:{{'Content-Type':'application/json','X-API-Key':apiKey}},body:JSON.stringify({{key:key,reviewed:false}})}});
      if(!r.ok){{alert('Failed: HTTP '+r.status+' (API key needed)');box.checked=!box.checked;return;}}
      row.remove();
    }}catch(e){{alert('Failed: '+e);box.checked=!box.checked;}}
  }});
}});

(function(){{
  // the refresh interval is kept in the browser
  var sel=document.getElementById('refresh');
  if(!sel)return;
  var KEY='sbom_refresh';
  var saved=parseInt(localStorage.getItem(KEY)||'1800',10);
  if(!saved) saved=1800;
  sel.value=String(saved);
  var timer=null;
  function apply(){{
    if(timer)clearInterval(timer);
    timer=setInterval(function(){{location.reload();}},parseInt(sel.value,10)*1000);
  }}
  sel.addEventListener('change',function(){{localStorage.setItem(KEY,sel.value);apply();}});
  apply();
}})();
</script></body></html>"""

PORTAL_HEAD = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SBOM: Supply Chain Security</title><style>
*{box-sizing:border-box;scrollbar-width:thin;scrollbar-color:rgba(49,95,189,.42) transparent}body{margin:0;background:#f3f5f9;color:#172033;font:14px/1.5 system-ui,sans-serif}

::-webkit-scrollbar{width:3px;height:3px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(49,95,189,.42);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:rgba(49,95,189,.68)}
::-webkit-scrollbar-corner{background:transparent}
header{position:sticky;top:0;z-index:30;background:linear-gradient(100deg,#0e2340 0%,#1a3a6d 58%,#24518f 100%);color:white;padding:14px max(20px,calc((100vw - 1450px)/2));box-shadow:0 3px 14px rgba(14,35,64,.32);border-bottom:3px solid #3f8fe0;display:flex;justify-content:space-between;align-items:center;gap:18px;flex-wrap:wrap}
.headleft{min-width:0}
.copy{flex:0 0 auto;display:inline-flex;align-items:center;gap:7px;padding:7px 16px;border:1px solid rgba(255,255,255,.32);border-radius:20px;background:rgba(255,255,255,.12);color:#dbe7f7;font-size:12.5px;letter-spacing:.3px;white-space:nowrap;box-shadow:inset 0 1px 0 rgba(255,255,255,.14)}
.copy b{color:#fff;font-weight:700;letter-spacing:.6px}
header h1{margin:0;font-size:23px;letter-spacing:.3px}header h1 a{color:#fff;text-decoration:none}header h1 a:hover{text-decoration:none;opacity:.92}header p{color:#bcd0ea;margin:4px 0 0;font-size:13px}
main{max-width:1450px;margin:22px auto;padding:0 18px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px}
.card.link{text-decoration:none;color:inherit}.card.link:hover{border-color:#315fbd;background:#f7faff}
.card,.panel{background:white;border:1px solid #e3e8f0;border-radius:11px;padding:15px}.card small{display:block;color:#68758b}.card strong{display:block;font-size:26px;margin-top:4px}
.card small.sub{margin-top:4px;font-size:11px;color:#7b879b}
.riskblock{margin-top:20px}.riskblock h2{margin:0 0 10px;font-size:16px;color:#2b3a55}
.riskcards .card{text-decoration:none;color:inherit;transition:transform .12s ease,box-shadow .12s ease}
.riskcards .card:hover{transform:translateY(-2px);box-shadow:0 6px 16px rgba(20,40,70,.14)}
.riskcards .card small{font-weight:bold;letter-spacing:.4px}
.card.critical{background:#fdeaea;border-color:#f0b6bb;color:#8d1b2c}.card.critical small{color:#a3243a}
.card.high{background:#fff0e2;border-color:#f3cfa4;color:#8a4a08}.card.high small{color:#a35c10}
.card.medium{background:#fff7df;border-color:#f0dfa4;color:#7a5600}.card.medium small{color:#93701a}
.card.low{background:#e9f7ee;border-color:#b6e0c4;color:#14653a}.card.low small{color:#1b7c4a}
.card.unknown{background:#eef1f6;border-color:#d5dbe5;color:#4a566b}.card.unknown small{color:#5b687e}
.panel{margin-top:16px}.toolbar{display:flex;gap:10px;margin:12px 0;flex-wrap:wrap;align-items:center}
input,select{padding:10px;border:1px solid #ccd4e2;border-radius:8px}input{flex:1;min-width:220px}
button{padding:9px 14px;border:1px solid #ccd4e2;border-radius:8px;background:#fff;cursor:pointer}button:hover{background:#eef2f9}
.tablewrap{overflow:auto}table{border-collapse:collapse;width:100%;min-width:1100px}td,th{padding:10px;border-bottom:1px solid #e5e9f0;text-align:left;vertical-align:top}th{background:#f8f9fc;color:#526078}
code{font-size:11px;overflow-wrap:anywhere}a{color:#315fbd}.risk{padding:2px 8px;border-radius:20px;background:#eef1f5;font-size:11px;font-weight:bold}
.critical,.high{background:#ffe3e3;color:#a51d2d}.medium{background:#fff0d4;color:#8a5700}.low{background:#e3f4e8;color:#176b37}
.notice{background:#fff8e8;padding:10px;border:1px solid #f0dfb4;border-radius:8px}.meta{color:#68758b;font-size:12px;margin-top:12px}
footer.foot{margin:26px auto 32px;padding:0 18px;display:flex;justify-content:center;align-items:center;gap:16px;flex-wrap:wrap;color:#8794a8;font-size:12px;letter-spacing:.2px}
footer.foot b{color:#68758b;font-weight:600}
footer.foot .refresh{display:inline-flex;align-items:center;gap:7px}
footer.foot .refresh select{padding:5px 8px;border:1px solid #ccd4e2;border-radius:7px;background:#fff;color:#46536b;font-size:12px}
footer.foot .refresh label{color:#68758b}
.dash{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:14px;margin-top:16px}
.dashpanel h2{font-size:12px;margin:0 0 14px;color:#526078;text-transform:uppercase;letter-spacing:.8px;font-weight:700}
.stackbar{display:flex;height:20px;border-radius:10px;overflow:hidden;background:#eef1f6;box-shadow:inset 0 0 0 1px rgba(20,40,70,.05)}
.stackbar span{display:block;height:100%;transition:width .3s ease}
.stackbar span.critical{background:#d9534f}.stackbar span.high{background:#f0a04b}.stackbar span.medium{background:#e8c65a}
.stackbar span.low{background:#5cb87c}.stackbar span.unknown{background:#a8b3c4}
.stackbar span.cached{background:#3f7fd0}.stackbar span.latest{background:#63b3ed}.stackbar span.historical{background:#c8d2e0}
.legend{display:flex;flex-wrap:wrap;gap:8px 18px;margin-top:12px;font-size:12px;color:#46536b}
.legend span{display:flex;align-items:center;gap:6px}
.legend i{width:10px;height:10px;border-radius:3px;display:inline-block}
.big{font-size:40px;font-weight:700;line-height:1;color:#1b2a44}
.bigrow{display:flex;align-items:baseline;gap:12px}
.card.kpi{border-top:3px solid #315fbd;position:relative}
.card.kpi:before{content:"";position:absolute;left:0;top:0;width:100%;height:3px;border-radius:11px 11px 0 0;background:#315fbd;opacity:.9}
.card.kpi.c1{border-top-color:#3f7fd0}.card.kpi.c2{border-top-color:#5cb87c}.card.kpi.c3{border-top-color:#f0a04b}
.card.kpi.c4{border-top-color:#d9534f}.card.kpi.c5{border-top-color:#8b5cf6}.card.kpi.c6{border-top-color:#00a2b8}
.card.kpi .klabel{display:block;color:#68758b;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-height:1.2em}
.card.kpi .kvalue{display:block;font-size:28px;font-weight:700;margin-top:6px;color:#16233c}
.pending{color:#8a5700;font-size:11px;font-weight:bold}
@media (max-width:900px){.dash{grid-template-columns:1fr}.cards{grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}}
@media (max-width:640px){
 main{margin:14px auto;padding:0 10px}
 header{padding:10px 12px;gap:8px}
 header h1{font-size:17px}header p{font-size:11.5px}
 .copy{font-size:10.5px;padding:5px 11px;letter-spacing:.1px}
 .cards{grid-template-columns:repeat(auto-fit,minmax(124px,1fr));gap:9px}
 .card,.panel{padding:12px;border-radius:10px}
 .card.kpi .kvalue{font-size:22px}.card.kpi .klabel{font-size:11px}
 .dash{gap:11px;margin-top:12px}
 .toolbar{gap:8px}
 .toolbar input,.toolbar select,input,select{min-width:0;width:100%}
 .toolbar button{width:100%}
 .tablewrap table{min-width:640px;font-size:12.5px}
 .tablewrap td,.tablewrap th{padding:7px 8px}
 .big{font-size:32px}
 footer.foot{margin:20px auto 24px;padding:0 12px;flex-direction:column;gap:10px}
}
</style></head><body><header><div class="headleft"><h1><a data-home="1" href="">SBOM: Supply Chain Security</a></h1><p>{{subtitle}}</p></div><div class="copy">Copyright &copy; {{year}} <b>AIFE in FEIT</b></div></header>
<main><section class="cards kpis">{{cards}}</section>
{{dashboard}}
<section class="riskblock"><h2>Risk by severity</h2><div class="cards riskcards">{{risk_cards}}</div>
<p class="meta">Reviewed findings are not counted here, the risk pages show the details.
<a data-rel="reviewed" href="reviewed">Reviewed findings: {{reviewed_total}}</a></p></section>
<section class="panel"><h2>Package inventory</h2><form class="toolbar" method="get" action="">
<input name="q" value="{{q}}" placeholder="Search package, version, hash, CVE…"><select name="scope">{{scopes}}</select><select name="eco">{{ecos}}</select><select name="risk">{{risks}}</select>
<button type="submit">Search</button><span class="meta">{{count}}</span></form>
<div class="tablewrap"><table id="tbl"><thead><tr><th>Ecosystem</th><th>Package</th><th>Version</th><th>Risk</th><th>License</th><th>Tarball</th><th>SHA256</th><th>Dependencies</th><th>Vulnerabilities</th></tr></thead><tbody>{{rows}}</tbody></table></div>
{{pager}}
<div class="meta">JSON schema: {{schema}} · full JSON ({{size}}) is in the reports directory, not linked here · <a data-rel="progress" href="progress">scan progress</a></div>{{notice}}</section></main>
<footer class="foot"><span>Developed by <b>Ateam+</b></span><span class="refresh"><label for="refresh">auto refresh</label>
<select id="refresh" title="How often the page reloads itself">
<option value="60">1 min</option><option value="300">5 min</option>
<option value="1800" selected>30 min</option><option value="3600">60 min</option></select></span></footer>

<script>
(function(){{
function appDir(){{
  var p=location.pathname;
  var i=p.lastIndexOf('/risk');
  if(i>=0)return p.slice(0,i+1);
  if(p.charAt(p.length-1)==='/')return p;
  var last=p.slice(p.lastIndexOf('/')+1);
  if(last===''||last==='progress'||last==='index.html')return p.slice(0,p.lastIndexOf('/')+1);
  return p+'/';
}}
  var dir=appDir();
  document.querySelectorAll('a[data-home]').forEach(function(a){{a.href=dir;}});
  document.querySelectorAll('a[data-rel]').forEach(function(a){{a.href=dir+a.getAttribute('data-rel');}});
}})();

(function(){{
  // the refresh interval is kept in the browser
  var sel=document.getElementById('refresh');
  if(!sel)return;
  var KEY='sbom_refresh';
  var saved=parseInt(localStorage.getItem(KEY)||'1800',10);
  if(!saved) saved=1800;
  sel.value=String(saved);
  var timer=null;
  function apply(){{
    if(timer)clearInterval(timer);
    timer=setInterval(function(){{location.reload();}},parseInt(sel.value,10)*1000);
  }}
  sel.addEventListener('change',function(){{localStorage.setItem(KEY,sel.value);apply();}});
  apply();
}})();
</script></body></html>"""


RISK_INDEX_HEAD = RISK_INDEX_HEAD.replace("__STYLE__", re.search(r"<style>(.*?)</style>", PORTAL_HEAD, re.S).group(1))
REVIEWED_HEAD = REVIEWED_HEAD.replace("__STYLE__", re.search(r"<style>(.*?)</style>", PORTAL_HEAD, re.S).group(1))


class IndexStore:
    """Lazy loaded compact index, the portal never needs the full report in memory."""

    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._rows = []
        self._mtime = None

    def rows(self):
        global scoped
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            with self._lock:
                self._rows, self._mtime = [], None
            return []
        with self._lock:
            if self._mtime == mtime:
                return self._rows
        rows = []
        scoped = False
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    try:
                        d = json.loads(line)
                    except ValueError:
                        continue
                    name = str(d.get("n", "")); version = str(d.get("v", ""))
                    level = str(d.get("r", "NONE")); lic = str(d.get("l", "UNKNOWN"))
                    tarball = str(d.get("t", "")); sha = str(d.get("h", ""))
                    deps = str(d.get("d", "")); links = d.get("x") or []
                    ids = " ".join(str(x.get("i", "")) for x in links)
                    haystack = (name + " " + version + " " + sha + " " + tarball + " " + lic + " " + ids).lower()
                    cached = bool(d.get("c")); latest = bool(d.get("n2"))
                    ecosystem = str(d.get("e", "npm"))
                    if "c" in d or "n2" in d:
                        scoped = True
                    rows.append((name, version, level, lic, tarball, sha, deps, links, haystack,
                                 cached, latest, ecosystem))
        except OSError as e:
            log.warning("Cannot read index: %s", e)
            return self._rows
        with self._lock:
            self._rows, self._mtime = rows, mtime
        log.info("Index loaded: %s rows (scope flags: %s)", len(rows), scoped)
        return rows


INDEX = None
scoped = False
SUMMARY = {"path": None, "mtime": None, "data": {}}


def summary_file():
    """Summary of the last completed scan, survives a restart."""
    path = ROOT / "summary.json"
    try:
        mtime = path.stat().st_mtime
    except OSError:
        SUMMARY["path"], SUMMARY["mtime"], SUMMARY["data"] = path, None, {}
        return {}
    if SUMMARY["mtime"] == mtime:
        return SUMMARY["data"]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        data = {}
    SUMMARY["path"], SUMMARY["mtime"], SUMMARY["data"] = path, mtime, data
    return data


def esc(value):
    import html as _html
    return _html.escape(str(value if value is not None else ""), quote=True)


def render_portal(rows, summary, query, state=None):
    """Server side pagination and search, the browser only receives one page."""
    summary = summary or {}
    packages = rows
    q = (query.get("q") or [""])[0].strip().lower()
    risk = (query.get("risk") or [""])[0].strip()
    scope = (query.get("scope") or ["relevant"])[0].strip() or "relevant"
    eco_filter = (query.get("eco") or [""])[0].strip()
    try:
        page = max(1, int((query.get("page") or ["1"])[0]))
    except ValueError:
        page = 1

    def in_scope(r):
        if not scoped or scope == "all":
            return True
        cached, latest = r[9], r[10]
        if scope == "cached":
            return cached
        if scope == "latest":
            return latest
        return cached or latest

    def matches_row(r):
        if eco_filter and r[11] != eco_filter:
            return False
        if not in_scope(r):
            return False
        if risk and r[2] != risk:
            return False
        return not q or q in r[8]

    hits = [r for r in packages if matches_row(r)]
    pages = max(1, (len(hits) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(page, pages)
    chunk = hits[(page - 1) * PAGE_SIZE: page * PAGE_SIZE]

    html_rows = []
    for name, version, level, license_, tarball, sha, deps, links, _hay, _cached, _latest, eco in chunk:
        vuln_html = "<br>".join(
            f'<a target="_blank" rel="noopener" href="{esc(x.get("u", ""))}">{esc(x.get("i", ""))}</a> ({esc(x.get("s", ""))})'
            for x in links) or "—"
        dep = ", ".join(deps.split(",")[:5]) if deps else ""
        html_rows.append("<tr>" + "".join([
            f"<td>{esc(eco)}</td><td>{esc(name)}</td><td>{esc(version)}</td>",
            f'<td><span class="risk {level.lower()}">{level}</span></td>',
            f"<td>{esc(license_)}</td><td>{esc(tarball or 'not found')}</td>",
            f"<td><code>{esc(sha or 'not calculated')}</code></td><td>{esc(dep)}</td><td>{vuln_html}</td>"
        ]) + "</tr>")
    body = "\n".join(html_rows) or '<tr><td colspan="8">No matching package versions.</td></tr>'

    scoped_total = sum(1 for r in packages if in_scope(r))
    count_text = f"{len(hits)} matching of {scoped_total} in scope"
    if scoped_total != len(packages):
        count_text += f" / {len(packages)} total"
    stats = index_stats(rows, REVIEWS.keys())
    if rows:
        cards = [("Packages", "Unique packages", stats["packages"]),
                 ("Versions", "Package versions", stats["versions"]),
                 ("Tarballs", "Tarballs hashed", stats["cached"]),
                 ("Vulnerable", "Versions with a vulnerability", stats["vulnerable"]),
                 ("Findings", "Vulnerability findings", stats["findings"]),
                 ("Dependencies", "Dependency edges", stats["edges"])]
    else:
        cards = [("Packages", "Unique packages", summary.get("unique_packages", 0)),
                 ("Versions", "Package versions", summary.get("package_versions", 0)),
                 ("Tarballs", "Tarballs hashed", summary.get("tarballs_scanned", 0)),
                 ("Vulnerable", "Versions with a vulnerability", summary.get("versions_with_vulnerabilities", 0)),
                 ("Findings", "Vulnerability findings", summary.get("vulnerability_findings", 0)),
                 ("Dependencies", "Dependency edges", summary.get("dependency_edges", 0))]
    card_html = "".join(f'<div class="card kpi c{i}" title="{esc(full)}"><span class="klabel">{esc(k)}</span>'
                        f'<span class="kvalue">{esc(v)}</span></div>'
                        for i, (k, full, v) in enumerate(cards, 1))
    severity = risk_counts(rows, REVIEWS.keys())
    if not rows:
        # no index yet, the numbers of the last scan are used
        severity = summary.get("severity") or {}
    risk_cards = "".join(
        f'<a class="card {l.lower()}" href="risk/{l.lower()}" data-rel="risk/{l}"><small>{l}</small>'
        f'<strong>{esc(severity.get(l, 0))}</strong></a>'
        for l in RISK_LEVELS)
    reviewed_total = len(REVIEWS.keys())
    dashboard = render_dashboard(rows, summary, REVIEWS.keys())
    risks = "".join(f'<option value="{esc(v)}"{" selected" if v == risk else ""}>{esc(v or "All severity")}</option>'
                    for v in ("", "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "PENDING", "UNKNOWN"))
    ecosystems = sorted({r[11] for r in packages})
    ecos = "".join(f'<option value="{esc(v)}"{" selected" if v == eco_filter else ""}>{esc(v or "All ecosystems")}</option>'
                    for v in [""] + ecosystems)
    scope_labels = {"relevant": "Registry relevant (cached or latest)", "all": "All versions",
                    "cached": "Cached tarballs only", "latest": "Latest version only"}
    scopes = "".join(f'<option value="{esc(k)}"{" selected" if k == scope else ""}>{esc(v)}</option>'
                     for k, v in scope_labels.items())
    if not scoped:
        scopes = '<option value="all">All versions (index without scope flags)</option>' 

    def link(target):
        return "?" + "&amp;".join([f"q={quote(q)}", f"risk={quote(risk)}", f"scope={quote(scope)}",
                                   f"eco={quote(eco_filter)}", f"page={target}"])

    pager = ""
    if pages > 1:
        prev = f'<a href="{link(max(1, page - 1))}">&larr; Prev</a>' if page > 1 else "&larr; Prev"
        nxt = f'<a href="{link(min(pages, page + 1))}">Next &rarr;</a>' if page < pages else "Next &rarr;"
        pager = (f'<div class="toolbar"><span class="meta">Page {page} / {pages} &middot; {len(hits)} matches</span>'
                 f"{prev} &nbsp; {nxt}</div>")
    notice = ""
    if state and state.get("running"):
        notice = ('<p class="notice">A scan is running &middot; this page shows the last completed report '
                  f'({esc(state.get("phase", ""))})</p>')
    elif summary.get("osv_error"):
        notice = f'<p class="notice">OSV query warning: {esc(summary["osv_error"])}</p>'
    subtitle = (f'Full registry scan · {esc(summary.get("generated_at", ""))} · '
                f'OSV {"enabled" if summary.get("osv_enabled", True) else "disabled"}')
    page = PORTAL_HEAD
    for key, value in {
            "subtitle": subtitle, "cards": card_html, "risk_cards": risk_cards,
            "dashboard": dashboard,
            "q": esc(q), "risks": risks, "scopes": scopes, "ecos": ecos,
            "count": count_text,
            "rows": body, "pager": pager, "reviewed_total": str(reviewed_total),
            "year": str(YEAR),
            "schema": esc(summary.get("schema", "")),
            "size": esc(summary.get("report_size", "—")), "notice": notice}.items():
        page = page.replace("{{" + key + "}}", value)
    return finish_page(page)


def is_portal_path(path):
    """The application root, with or without a reverse proxy path prefix."""
    if path.endswith("/index.html"): return True
    last = path.rstrip("/").split("/")[-1]
    return last == "" or "." not in last


def index_stats(rows, reviewed):
    """Global counters from the index, the reviewed findings are not counted."""
    packages = set()
    versions = cached = vulnerable = findings = edges = 0
    for name, version, _risk, _lic, tarball, _sha, deps, links, _hay, is_cached, is_latest, eco in rows:
        packages.add(name)
        versions += 1
        if tarball:
            cached += 1
        if deps:
            edges += deps.count(",") + 1
        live = 0
        for link in links:
            key = review_store.finding_key(eco, name, version, link.get("i", ""))
            if key in reviewed:
                continue
            live += 1
        if live:
            vulnerable += 1
        findings += live
    return {"packages": len(packages), "versions": versions, "cached": cached,
            "vulnerable": vulnerable, "findings": findings, "edges": edges}


def risk_counts(rows, reviewed):
    """Findings per severity level, only the relevant versions and without the reviewed ones."""
    counts = {}
    for name, version, _risk, _lic, _tarball, _sha, _deps, links, _hay, cached, latest, eco in rows:
        if not (cached or latest):
            continue
        for link in links:
            level = (link.get("s") or "UNKNOWN").upper()
            key = review_store.finding_key(eco, name, version, link.get("i", ""))
            if key in reviewed:
                continue
            counts[level] = counts.get(level, 0) + 1
    return counts


def dashboard_stats(rows, reviewed):
    """Numbers for the dashboard panels, the relevant versions only."""
    levels = {}
    ecosystems = {}
    packages = set()
    cached = latest = historical = 0
    findings = 0
    for name, version, _risk, _lic, _tarball, _sha, _deps, links, _hay, is_cached, is_latest, eco in rows:
        packages.add(name)
        ecosystems[eco] = ecosystems.get(eco, 0) + 1
        if is_cached and is_latest:
            cached += 1
        elif is_cached:
            cached += 1
        elif is_latest:
            latest += 1
        else:
            historical += 1
        if not (is_cached or is_latest):
            continue
        for link in links:
            key = review_store.finding_key(eco, name, version, link.get("i", ""))
            if key in reviewed:
                continue
            level = (link.get("s") or "UNKNOWN").upper()
            levels[level] = levels.get(level, 0) + 1
            findings += 1
    return {"levels": levels, "ecosystems": ecosystems, "packages": len(packages),
            "cached": cached, "latest": latest, "historical": historical,
            "findings": findings, "reviewed": len(reviewed)}


def stack_bar(parts, total):
    """A stacked bar of the given (label, value, color) parts."""
    if not total:
        return '<div class="stackbar"></div><div class="legend">nothing yet</div>'
    bar = "".join(f'<span style="width:{value * 100.0 / total:.2f}%;background:{color}"></span>'
                  for label, value, color in parts if value)
    legend = "".join(f'<span><i style="background:{color}"></i>{esc(label)} {value}'
                     f' ({format(value * 100.0 / total, ".1f")}%)</span>'
                     for label, value, color in parts if value)
    return f'<div class="stackbar">{bar}</div><div class="legend">{legend}</div>'


def render_dashboard(rows, summary, reviewed):
    """The dashboard panels of the portal."""
    stats = dashboard_stats(rows, reviewed)
    total = stats["findings"]
    colors = {"CRITICAL": "#d9534f", "HIGH": "#f0a04b", "MEDIUM": "#e8c65a",
              "LOW": "#5cb87c", "UNKNOWN": "#a8b3c4"}
    levels = [(l, stats["levels"].get(l, 0), colors[l]) for l in RISK_LEVELS]
    scope = [("Cached tarball", stats["cached"], "#3f7fd0"),
             ("Latest version", stats["latest"], "#63b3ed"),
             ("Historical version", stats["historical"], "#c8d2e0")]
    ecosystems = sorted(stats["ecosystems"].items(), key=lambda x: -x[1])
    eco_colors = ["#3f7fd0", "#63b3ed", "#2f6fb5", "#8ab8ea", "#1d5a94"]
    eco_parts = [(name, count, eco_colors[i % len(eco_colors)])
                 for i, (name, count) in enumerate(ecosystems)]
    eco_total = sum(count for _, count in ecosystems)
    panels = [
        ("Findings by severity", stack_bar(levels, total)),
        ("Registry scope", stack_bar(scope, stats["cached"] + stats["latest"] + stats["historical"])),
        ("Ecosystems", stack_bar(eco_parts, eco_total)),
        ("Reviewed findings",
         f'<div class="bigrow"><div class="big">{stats["reviewed"]}</div>'
         f'<div class="meta">findings are marked as reviewed,<br>they leave the counters and the alerts.</div></div>'
         f'<p class="meta"><a data-rel="reviewed" href="reviewed">open the reviewed list</a></p>'),
    ]
    body = "".join(f'<section class="panel dashpanel"><h2>{esc(title)}</h2>{content}</section>'
                   for title, content in panels)
    return f'<section class="dash">{body}</section>'


def finish_page(page, where="report portal"):
    """Report the leftover placeholders and restore the braces of the template."""
    missing = sorted(set(re.findall(r"\{\{(\w+)\}\}", page)))
    if missing:
        log.error("Unreplaced placeholder in the %s: %s", where, missing)
    return page.replace("{{", "{").replace("}}", "}")


def render_risk_index():
    """Overview of every severity level."""
    rows = INDEX.rows() if INDEX else []
    reviewed = REVIEWS.keys()
    counts = risk_counts(rows, reviewed)
    done = {}
    for f in reviewed_findings(rows, reviewed):
        done[f["severity"]] = done.get(f["severity"], 0) + 1
    cards = "".join(f'<a class="card {l.lower()}" data-rel="risk/{l.lower()}" href="risk/{l.lower()}">'
                    f'<small>{l}</small><strong>{counts.get(l, 0)}</strong>'
                    f'<small class="sub">{done.get(l, 0)} reviewed</small></a>' for l in RISK_LEVELS)
    exports = " · ".join(f'<a data-rel="risks/{l.lower()}.json" href="risks/{l.lower()}.json">{l.lower()}.json</a>'
                         for l in RISK_LEVELS)
    exports += f' · <a data-rel="reviewed" href="reviewed">reviewed.json ({sum(done.values())})</a>'
    html = RISK_INDEX_HEAD
    for key, value in {"subtitle": "Findings per severity level · cached or newest versions only · "
                                   "reviewed findings are not counted",
                       "cards": cards, "links": "", "exports": exports, "year": str(YEAR)}.items():
        html = html.replace("{{" + key + "}}", value)
    return finish_page(html, "risk index")


def reviewed_findings(rows, reviewed):
    """The reviewed findings of the current index, plus the keys that are not in it any more."""
    found = []
    seen = set()
    for name, version, _risk, _lic, _tarball, sha, _deps, links, _hay, cached, latest, eco in rows:
        for link in links:
            key = review_store.finding_key(eco, name, version, link.get("i", ""))
            if key not in reviewed:
                continue
            seen.add(key)
            found.append({
                "key": key, "name": name, "version": version, "id": link.get("i", ""),
                "severity": (link.get("s") or "UNKNOWN").upper(), "sha": sha,
                "score": link.get("sc"),
                "url": link.get("u") or ("https://osv.dev/vulnerability/" + link.get("i", "")),
                "cached": cached, "latest": latest, "orphan": False})
    for key in sorted(reviewed - seen):
        eco, _, rest = key.partition(":")
        name, _, version = rest.rpartition("@")
        advisory = rest.rpartition(":")[2]
        found.append({"key": key, "name": name, "version": version, "id": advisory,
                      "severity": "UNKNOWN", "sha": "", "score": None, "url": "",
                      "cached": False, "latest": False, "orphan": True})
    return found


def render_reviewed_page(query):
    """All the findings that were marked as reviewed."""
    rows = INDEX.rows() if INDEX else []
    reviewed = REVIEWS.keys()
    level = (query.get("level") or [""])[0].strip().upper()
    try:
        page = max(1, int((query.get("page") or ["1"])[0]))
    except ValueError:
        page = 1
    findings = reviewed_findings(rows, reviewed)
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    if level:
        findings = [f for f in findings if f["severity"] == level]
    pages = max(1, (len(findings) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(page, pages)
    chunk = findings[(page - 1) * PAGE_SIZE: page * PAGE_SIZE]
    body = []
    for f in chunk:
        relevance = []
        if f["cached"]: relevance.append("cached")
        if f["latest"]: relevance.append("latest")
        if f["orphan"]: relevance.append("not in the index")
        body.append("<tr>" +
            f'<td><input type="checkbox" class="checkbox" checked data-k="{quote(f["key"], safe="")}"></td>'
            f'<td>{esc(f["name"])}</td><td>{esc(f["version"])}</td>'
            + (f'<td><a target="_blank" rel="noopener" href="{esc(f["url"])}">{esc(f["id"])}</a></td>'
               if f["url"] else f'<td>{esc(f["id"])}</td>')
            + f'<td><span class="risk {f["severity"].lower()}">{esc(f["severity"])}</span></td>'
            f'<td>{esc(f["score"] if f["score"] is not None else "")}</td>'
            f'<td><code>{esc((f["sha"] or "")[:16])}</code></td>'
            f'<td>{esc(", ".join(relevance) or "historical")}</td></tr>')
    cards = "".join(f'<a class="card {l.lower()}" href="reviewed?level={l}" data-rel="reviewed?level={l}">'
                    f'<small>{l}</small><strong>{counts.get(l, 0)}</strong></a>' for l in RISK_LEVELS)
    cards += f'<div class="card"><small>reviewed total</small><strong>{sum(counts.values())}</strong></div>'
    nav = ""
    if pages > 1:
        prev = f'<a href="?level={level or ""}&amp;page={max(1, page - 1)}">&larr; Prev</a>' if page > 1 else "&larr; Prev"
        nxt = f'<a href="?level={level or ""}&amp;page={min(pages, page + 1)}">Next &rarr;</a>' if page < pages else "Next &rarr;"
        nav = f'<span class="meta">Page {page} / {pages}</span> {prev} &nbsp; {nxt}'
    else:
        nav = f'<span class="meta">Page {page} / {pages}</span>'
    exports = " · ".join(f'<a data-rel="risks/{l.lower()}.json" href="risks/{l.lower()}.json">{l.lower()}.json</a>'
                         for l in RISK_LEVELS)
    html = REVIEWED_HEAD
    for key, value in {
            "subtitle": f"{len(findings)} reviewed findings · untick a row to put it back into the risk",
            "cards": cards, "rows": "\n".join(body) or '<tr><td colspan="8">Nothing is reviewed yet.</td></tr>',
            "pager": "", "nav": nav, "exports": exports,
            "level": level, "level_label": level or "all levels", "year": str(YEAR),
            "other_level": "" if level else "CRITICAL"}.items():
        html = html.replace("{{" + key + "}}", value)
    return finish_page(html, "reviewed page")


def render_risk_page(level, query):
    """One page per severity level, the findings come from the index."""
    rows = INDEX.rows() if INDEX else []
    reviewed = REVIEWS.keys()
    q = (query.get("q") or [""])[0].strip().lower()
    show_reviewed = (query.get("show") or ["0"])[0] == "1"
    try:
        page = max(1, int((query.get("page") or ["1"])[0]))
    except ValueError:
        page = 1
    findings = []
    for name, version, _risk, _lic, _tarball, sha, _deps, links, haystack, cached, latest, eco in rows:
        if not (cached or latest):
            continue
        for link in links:
            if (link.get("s") or "").upper() != level:
                continue
            key = review_store.finding_key(eco, name, version, link.get("i", ""))
            if q and q not in haystack:
                continue
            findings.append({
                "key": key, "name": name, "version": version, "id": link.get("i", ""),
                "severity": (link.get("s") or "").upper(), "sha": sha,
                "score": link.get("sc"),
                "url": link.get("u") or ("https://osv.dev/vulnerability/" + link.get("i", "")),
                "reviewed": key in reviewed, "cached": cached, "latest": latest})
    if not show_reviewed:
        findings = [f for f in findings if not f["reviewed"]]
    pages = max(1, (len(findings) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(page, pages)
    chunk = findings[(page - 1) * PAGE_SIZE: page * PAGE_SIZE]
    body = []
    for f in chunk:
        relevance = []
        if f["cached"]: relevance.append("cached")
        if f["latest"]: relevance.append("latest")
        body.append("<tr class=\"%s\">" % ("reviewed" if f["reviewed"] else "") +
            f'<td><input type="checkbox" class="checkbox" data-k="{quote(f["key"], safe="")}"{" checked" if f["reviewed"] else ""}></td>'
            f'<td>{esc(f["name"])}</td><td>{esc(f["version"])}</td>'
            f'<td><a target="_blank" rel="noopener" href="{esc(f["url"])}">{esc(f["id"])}</a></td>'
            f'<td><span class="risk {f["severity"].lower()}">{f["severity"]}</span></td>'
            f'<td>{esc(f["score"] if f["score"] is not None else "")}</td>'
            f'<td><code>{esc((f["sha"] or "")[:16])}</code></td>'
            f'<td>{esc(", ".join(relevance) or "historical")}</td></tr>')
    exports = " · ".join(f'<a data-rel="risks/{l.lower()}.json" href="risks/{l.lower()}.json">{l.lower()}.json</a>'
                         for l in RISK_LEVELS)
    nav = ""
    if pages > 1:
        prev = f'<a href="?page={max(1, page - 1)}&show={1 if show_reviewed else 0}">&larr; Prev</a>' if page > 1 else "&larr; Prev"
        nxt = f'<a href="?page={min(pages, page + 1)}&show={1 if show_reviewed else 0}">Next &rarr;</a>' if page < pages else "Next &rarr;"
        nav = f'<span class="meta">Page {page} / {pages}</span> {prev} &nbsp; {nxt}'
    else:
        nav = f'<span class="meta">Page {page} / {pages}</span>'
    html = RISK_HEAD
    for key, value in {
            "level": level, "level_class": level.lower(), "title": f"Risks · {level}",
            "year": str(YEAR),
            "subtitle": f"{len(findings)} findings at {level} · cached or newest versions only · "
                        f"reviewed findings leave the statistics and the alerts",
            "rows": "\n".join(body) or '<tr><td colspan="8">No findings.</td></tr>',
            "pager": "", "nav": nav, "exports": exports,
            "show_label": "on" if show_reviewed else "off",
            "show_other": "0" if show_reviewed else "1"}.items():
        html = html.replace("{{" + key + "}}", value)
    return finish_page(html, "risk page")


def matches(path, candidate):
    """Match a route by suffix so a reverse proxy path prefix keeps working."""
    return path == candidate or path.endswith(candidate)


def reviewed_route(path):
    """True when the path is the reviewed page."""
    idx = path.rfind(REVIEWED_PATH)
    return idx >= 0


def risk_route(path):
    """Severity level of a risk page path, "" for the index, None when it is not a risk page."""
    idx = path.rfind(RISK_PATH)
    if idx < 0:
        return None
    level = path[idx + len(RISK_PATH):].strip("/").upper()
    return level if level in RISK_LEVELS else ""


class ReportHandler(SimpleHTTPRequestHandler):
    server_version = "verdaccio-supply-chain-report/1.0"
    protocol_version = "HTTP/1.1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.address_string(), fmt % args)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def _cookie_token(self):
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE:
                return unquote(value)
        return ""

    def _query_token(self, query):
        for value in parse_qs(query).get("token", []):
            if self._token_ok(value):
                return value
        return ""

    def _token_ok(self, value):
        if not TOKEN:
            return True
        return hmac.compare_digest(value.encode("utf-8"), TOKEN.encode("utf-8"))

    def _authorized(self, parsed):
        if not TOKEN:
            return True
        header = self.headers.get("Authorization", "")
        if header.lower().startswith("bearer ") and self._token_ok(header[7:].strip()):
            return True
        if self._token_ok(self._cookie_token()):
            return True
        return bool(self._query_token(parsed.query))

    def _redirect_clean(self, path):
        self.send_response(302)
        self.send_header("Location", path)
        self.send_header("Set-Cookie", f"{COOKIE}={quote(TOKEN, safe='')}; HttpOnly; SameSite=Strict; Path=/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _unauthorized(self):
        self._json(401, {"error": "unauthorized",
                         "hint": "pass ?token=<REPORT_TOKEN> or Authorization: Bearer <REPORT_TOKEN>"})

    def _json(self, status, payload, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _health(self):
        self._json(200, {"status": "ok", "report_dir": str(ROOT), "auth": "token" if TOKEN else "open"})

    def _review(self, query):
        """Mark a finding as reviewed, needs the review API key."""
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            self._json(400, {"error": "invalid_json"})
            return
        key = unquote((payload.get("key") or "").strip())
        reviewed = payload.get("reviewed", True)
        if not key:
            self._json(400, {"error": "missing_key"})
            return
        supplied = self.headers.get("X-API-Key") or ""
        if not supplied:
            token = (query.get("api_key") or [""])[0]
            supplied = token
        if not hmac.compare_digest(supplied.encode("utf-8"), REVIEW_API_KEY.encode("utf-8")):
            self._json(401, {"error": "invalid_api_key", "hint": "send the key in the X-API-Key header"})
            return
        state = REVIEWS.set(key, bool(reviewed))
        self._json(200, {"key": key, "reviewed": state, "count": len(REVIEWS.keys())})

    def _html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _portal(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _scan_status(self):
        self._json(200, CONTROL.status())

    def _progress_page(self):
        body = PROGRESS_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _trigger_scan(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        if LOCK.held_by_other():
            self._json(429, {"error": "another_scanner_active",
                             "detail": "another scanner is working on this report directory",
                             **CONTROL.status()}, {"Retry-After": RETRY_AFTER})
            return
        accepted, detail = CONTROL.request()
        if not accepted:
            self._json(429, {"error": "scan_in_progress", "detail": detail, **CONTROL.status()},
                       {"Retry-After": RETRY_AFTER})
            return
        self._json(202, {"status": "accepted", "detail": detail, **CONTROL.status()})

    def _handle(self, body):
        """Never drop the connection, a broken page answers with an error."""
        try:
            self._route(body)
        except Exception:
            log.exception("Request failed: %s", self.path)
            try:
                self._json(500, {"error": "internal_error", "path": self.path})
            except Exception:
                pass

    def _route(self, body):
        parsed = urlparse(self.path)
        if matches(parsed.path, HEALTH_PATH):
            self._health()
            return
        if not self._authorized(parsed):
            self._unauthorized()
            return
        if any(matches(parsed.path, p) for p in SCAN_STATUS_PATHS):
            self._scan_status()
            return
        if TOKEN and "token" in parse_qs(parsed.query):
            clean = dict(parse_qs(parsed.query))
            clean.pop("token", None)
            self._redirect_clean(parsed._replace(query=urlencode(clean, doseq=True)).geturl())
            return
        if matches(parsed.path, PROGRESS_PATH):
            self._progress_page()
            return
        if reviewed_route(parsed.path):
            self._html(render_reviewed_page(parse_qs(parsed.query)))
            return
        level = risk_route(parsed.path)
        if level is not None:
            if level:
                self._html(render_risk_page(level, parse_qs(parsed.query)))
            else:
                self._html(render_risk_index())
            return
        if is_portal_path(parsed.path):
            rows = INDEX.rows()
            status = CONTROL.status()
            summary = dict(summary_file() or status.get("last_summary") or {})
            if status.get("last_error"):
                summary["osv_error"] = status["last_error"]
            self._portal(render_portal(rows, summary, parse_qs(parsed.query), status))
            return
        handle = self.send_head()
        if handle is None:
            return
        try:
            if body:
                self.copyfile(handle, self.wfile)
        finally:
            handle.close()

    def send_head(self):
        parts = [p for p in urlparse(self.path).path.split("/") if p]
        if any(p.startswith(".") for p in parts):
            self.send_error(404, "Not Found")
            return None
        return super().send_head()

    def translate_path(self, path):
        """Serve report files when a reverse proxy keeps its path prefix."""
        translated = super().translate_path(path)
        if os.path.exists(translated):
            return translated
        clean = path.split("?", 1)[0].split("#", 1)[0]
        words = [w for w in clean.split("/") if w]
        trailing = clean.endswith("/")
        for i in range(1, len(words) + 1):
            suffix = "/" + "/".join(words[i:])
            if trailing and not suffix.endswith("/"):
                suffix += "/"
            candidate = super().translate_path(suffix)
            if os.path.exists(candidate):
                return candidate
        return translated

    def do_GET(self):
        self._handle(body=True)

    def do_HEAD(self):
        self._handle(body=False)

    def do_POST(self):
        parsed = urlparse(self.path)
        if matches(parsed.path, "/api/review"):
            self._review(parse_qs(parsed.query))
            return
        if not matches(parsed.path, SCAN_PATH):
            self._json(404, {"error": "not_found", "path": parsed.path})
            return
        if not self._authorized(parsed):
            self._unauthorized()
            return
        self._trigger_scan()


def start_server():
    global INDEX
    ROOT.mkdir(parents=True, exist_ok=True)
    if INDEX is None:
        INDEX = IndexStore(ROOT / "index.jsonl")
    httpd = ThreadingHTTPServer((BIND, PORT), ReportHandler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, name="report-http", daemon=True)
    thread.start()
    log.info("Report server listening on http://%s:%s/ (dir=%s, auth=%s)",
             BIND, PORT, ROOT, "token" if TOKEN else "open")
    return httpd


if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(),
                        format="{{asctime}} {{levelname}} {{message}}")
    server = start_server()
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        server.shutdown()
