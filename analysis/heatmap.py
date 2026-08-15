"""Interactive fault susceptibility heatmap.

Self-contained HTML, no build step, no CDN. X axis = instruction index in the
golden trace, Y axis = skip width k, colour = outcome class. Toggle between
base and hardened and watch the red move.
"""
import sys, json, html
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness"))

from elftools.elf.elffile import ELFFile
from faultlab.target import Target, boot_vectors
from faultlab.faults import single_fault_sweep, FaultModel, Outcome
from faultlab.campaign import run_campaign, golden_length
from faultlab.backend.unicorn_backend import UnicornBackend

FW = Path(__file__).resolve().parents[1] / "firmware" / "build"

def fns_of(bd):
    out = []
    with open(f"{bd}/fw.elf", "rb") as fh:
        for s in ELFFile(fh).get_section_by_name(".symtab").iter_symbols():
            if s["st_info"]["type"] == "STT_FUNC" and s.name:
                out.append((s["st_value"] & ~1, max(s["st_size"], 2), s.name))
    return sorted(out)

def whichfn(f, pc):
    for a, sz, n in f:
        if a <= pc < a + sz:
            return n
    return "?"

def collect(variant, vector_name, opt="-O2", limit=900):
    bd = str(FW / f"secureboot-{variant}{opt}")
    vec = {v.name: v for v in boot_vectors()}[vector_name]
    glen, _, _ = golden_length(bd, vec)
    span = min(glen, limit)
    t = Target.load(bd); f = fns_of(bd)
    be = UnicornBackend(t); be.reset(vec.writes(t)); _, seq = be.trace(glen * 3)
    fs = single_fault_sweep(range(0, span), models=(FaultModel.SKIP,), skip_widths=(1, 2, 3, 4))
    r = run_campaign(bd, vec, "boot", fs, workers=4)
    cells = [{"t": row.trigger, "k": row.value, "o": row.outcome,
              "f": whichfn(f, seq[row.trigger] if row.trigger < len(seq) else 0)}
             for row in r.rows]
    return {"variant": variant, "vector": vector_name, "golden": glen, "span": span,
            "cells": cells, "counts": r.counts(), "rate": round(r.rate)}

def build_data():
    return {f"{v}|{vec}": collect(v, vec)
            for v in ("base", "hardened") for vec in ("forged", "rollback")}

TPL = """<!doctype html><meta charset=utf-8><title>faultlab &mdash; susceptibility map</title>
<style>
:root{--bg:#0a0e12;--fg:#c8d6c8;--grid:#1a2229;--accent:#7dd3a0}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:13px/1.5 ui-monospace,'SF Mono',Menlo,monospace;padding:28px}
h1{font-size:15px;font-weight:500;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);margin:0 0 4px}
.sub{color:#5c6b74;margin-bottom:22px;font-size:12px}
.ctl{display:flex;gap:8px;margin-bottom:18px;flex-wrap:wrap}
button{background:#111820;color:var(--fg);border:1px solid var(--grid);padding:7px 14px;
  font:inherit;cursor:pointer;letter-spacing:.06em}
button.on{border-color:var(--accent);color:var(--accent);background:#0e1a14}
canvas{border:1px solid var(--grid);display:block;image-rendering:pixelated;width:100%;height:auto}
.legend{display:flex;gap:16px;margin:14px 0;flex-wrap:wrap;font-size:11px;align-items:center}
.sw{width:11px;height:11px;display:inline-block;margin-right:6px;vertical-align:-1px}
.stats{margin-top:16px;border-top:1px solid var(--grid);padding-top:14px;font-size:12px}
.stats b{color:var(--accent);font-weight:500}
#tip{position:fixed;background:#111820;border:1px solid var(--grid);padding:7px 10px;
  font-size:11px;pointer-events:none;opacity:0;transition:opacity .1s;z-index:9}
.axis{color:#5c6b74;font-size:11px;margin-top:6px}
</style>
<h1>Fault susceptibility map</h1>
<div class=sub>Cortex-M3 secure boot &middot; instruction-skip campaign &middot; each column = one instruction in the golden trace, each row = skip width k</div>
<div class=ctl id=ctl></div>
<canvas id=c></canvas>
<div class=axis>&larr; instruction index in golden trace &rarr;</div>
<div class=legend id=lg></div>
<div class=stats id=st></div>
<div id=tip></div>
<script>
const DATA = __DATA__;
const COLORS = {0:'#1b2a20',1:'#2d3640',2:'#3d3420',3:'#8a7a2e',4:'#ff3b3b',5:'#ff3b3b'};
const NAMES = {0:'OK',1:'CRASH',2:'HANG',3:'SDC',4:'SEC_BYPASS',5:'SAFETY_VIOLATION'};
let key='base|forged';
const c=document.getElementById('c'), x=c.getContext('2d'), tip=document.getElementById('tip');
document.getElementById('ctl').innerHTML=Object.keys(DATA).map(k=>
  `<button data-k="${k}">${k.replace('|',' \\u00b7 ')}</button>`).join('');
document.getElementById('lg').innerHTML=Object.entries(NAMES).map(([k,v])=>
  `<span><i class=sw style="background:${COLORS[k]}"></i>${v}</span>`).join('');
document.querySelectorAll('#ctl button').forEach(b=>b.onclick=()=>{key=b.dataset.k;draw()});
function draw(){
  const d=DATA[key], W=d.span, H=4, S=Math.max(1,Math.floor(1600/W));
  c.width=W*S; c.height=H*14;
  x.fillStyle='#0a0e12'; x.fillRect(0,0,c.width,c.height);
  for(const cell of d.cells){
    x.fillStyle=COLORS[cell.o];
    x.fillRect(cell.t*S,(cell.k-1)*14,S,13);
  }
  document.querySelectorAll('#ctl button').forEach(b=>b.classList.toggle('on',b.dataset.k===key));
  const ex=d.counts.SEC_BYPASS+d.counts.SAFETY_VIOLATION;
  document.getElementById('st').innerHTML=
    `golden trace <b>${d.golden}</b> instrs &middot; swept first <b>${d.span}</b> &middot; `+
    `<b>${d.cells.length}</b> experiments at <b>${d.rate.toLocaleString()}</b> runs/s<br>`+
    Object.entries(d.counts).map(([k,v])=>`${k} <b>${v}</b>`).join(' &middot; ')+
    `<br>exploitable sites: <b>${ex}</b>`;
  c.onmousemove=e=>{
    const r=c.getBoundingClientRect();
    const t=Math.floor((e.clientX-r.left)/r.width*W), k=Math.floor((e.clientY-r.top)/r.height*H)+1;
    const hit=d.cells.find(z=>z.t===t&&z.k===k);
    if(hit){tip.style.opacity=1;tip.style.left=(e.clientX+14)+'px';tip.style.top=(e.clientY+14)+'px';
      tip.innerHTML=`instr ${t} &middot; skip k=${k}<br>${hit.f}()<br><b>${NAMES[hit.o]}</b>`;}
    else tip.style.opacity=0;
  };
  c.onmouseleave=()=>tip.style.opacity=0;
}
draw();
</script>"""
if __name__ == "__main__":
    # REQUIRED: campaigns use the spawn start method, which re-imports this
    # module in every worker. Without this guard each worker would launch its
    # own campaign and the process tree would explode.
    data = build_data()
    out = Path(__file__).parent / "heatmap.html"
    out.write_text(TPL.replace("__DATA__", json.dumps(data)))
    print(f"wrote {out}  ({out.stat().st_size//1024} KB)")
    for k, v in data.items():
        print(f"  {k:22s} span={v['span']:5d} bypass={v['counts']['SEC_BYPASS']:4d} rate={v['rate']:,}/s")
