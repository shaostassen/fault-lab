"""Interactive fault susceptibility heatmap, across both architectures.

Self-contained HTML, no build step, no CDN. X axis = instruction index in the
golden trace, Y axis = skip width k, colour = outcome class. Toggle between
base and hardened and watch the red move -- and between Cortex-M3 and RV32I,
where the same C countermeasures leave a visibly different residue.

Controls are grouped (architecture / variant / vector) rather than presented
as one flat list of every combination, because the comparison the campaign
data actually supports is one-axis-at-a-time: hold vector and variant, flip
the architecture, and the difference on screen is attributable.

The two architectures are NOT aligned instruction-for-instruction on the x
axis. RV32I needs roughly 1.5x more instructions to express the same C, so
column 400 is a different point in the program on each. Compare the shape and
the density of red, not a specific column.
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

def collect(isa, variant, vector_name, opt="-O2", limit=None):
    suffix = "" if isa == "cm3" else f"-{isa}"
    bd = str(FW / f"secureboot-{variant}{opt}{suffix}")
    vec = {v.name: v for v in boot_vectors()}[vector_name]
    glen, _, _ = golden_length(bd, vec)
    # Whole golden trace by default: at ~37k runs/s a full 8,119-instruction
    # sweep is ~1s, and capping it at 900 hid the hardened -O2 survivors
    # (triggers 8105/8106) -- the one thing this figure most needs to show.
    span = glen if limit is None else min(glen, limit)
    t = Target.load(bd); f = fns_of(bd)
    be = UnicornBackend(t); be.reset(vec.writes(t)); _, seq = be.trace(glen * 3)
    fs = single_fault_sweep(range(0, span), models=(FaultModel.SKIP,), skip_widths=(1, 2, 3, 4))
    r = run_campaign(bd, vec, "boot", fs, workers=4)
    # Compact encoding, because the full-trace sweep makes the naive one huge
    # (5.5 MB of JSON, most of it repeated function-name strings).
    #
    #   * The function is a property of the COLUMN, not of each cell -- it is
    #     just whichever function the golden trace was in at that instruction --
    #     so it is stored once per column as an index into `fns`, not once per
    #     (trigger, width) pair. That alone removes 3/4 of the strings.
    #   * ~94% of cells are OK, so only non-OK cells are emitted and the
    #     renderer paints OK as the background. Lossless: absent == OK.
    fns, fidx = [], {}
    fcol = []
    for t_i in range(span):
        name = whichfn(f, seq[t_i] if t_i < len(seq) else 0)
        if name not in fidx:
            fidx[name] = len(fns); fns.append(name)
        fcol.append(fidx[name])
    cells = [[row.trigger, row.value, row.outcome]
             for row in r.rows if row.outcome != int(Outcome.OK)]
    return {"isa": isa, "variant": variant, "vector": vector_name,
            "golden": glen, "span": span, "cells": cells,
            "fns": fns, "fcol": fcol,
            # Explicit: `cells` holds only non-OK results now, so it is no
            # longer the experiment count.
            "total": len(r.rows),
            "counts": r.counts(), "rate": round(r.rate)}

ISAS = ("cm3", "rv32")
VARIANTS = ("base", "hardened")
VECTORS = ("forged", "rollback")


def build_data():
    return {f"{i}|{v}|{vec}": collect(i, v, vec)
            for i in ISAS for v in VARIANTS for vec in VECTORS}

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
/* Explicit height, not auto. The canvas is up to 12,430 x 56 px -- an aspect
   ratio near 220:1 -- so `height:auto` collapses it to a ~14px strip at full
   width and the four skip-width rows become unreadable. Fixing the displayed
   height stretches the rows back to a legible band; `pixelated` keeps the
   cell edges crisp rather than blurring rare single-column results away. */
canvas{border:1px solid var(--grid);display:block;image-rendering:pixelated;width:100%;height:132px}
.legend{display:flex;gap:16px;margin:14px 0;flex-wrap:wrap;font-size:11px;align-items:center}
.sw{width:11px;height:11px;display:inline-block;margin-right:6px;vertical-align:-1px}
.stats{margin-top:16px;border-top:1px solid var(--grid);padding-top:14px;font-size:12px}
.stats b{color:var(--accent);font-weight:500}
#tip{position:fixed;background:#111820;border:1px solid var(--grid);padding:7px 10px;
  font-size:11px;pointer-events:none;opacity:0;transition:opacity .1s;z-index:9}
.axis{color:#5c6b74;font-size:11px;margin-top:6px}
</style>
<h1>Fault susceptibility map</h1>
<div class=sub id=sub></div>
<div class=ctl id=ctl-isa></div>
<div class=ctl id=ctl-variant></div>
<div class=ctl id=ctl-vector></div>
<canvas id=c></canvas>
<div class=axis>&larr; instruction index in golden trace &rarr;</div>
<div class=legend id=lg></div>
<div class=stats id=st></div>
<div id=tip></div>
<script>
const DATA = __DATA__;
const COLORS = {0:'#1b2a20',1:'#2d3640',2:'#3d3420',3:'#8a7a2e',4:'#ff3b3b',5:'#ff3b3b'};
const NAMES = {0:'OK',1:'CRASH',2:'HANG',3:'SDC',4:'SEC_BYPASS',5:'SAFETY_VIOLATION'};
const ISA_LABEL={cm3:'Cortex-M3',rv32:'RV32I'};
let sel={isa:'cm3',variant:'base',vector:'forged'};
const c=document.getElementById('c'), x=c.getContext('2d'), tip=document.getElementById('tip');
const uniq=i=>[...new Set(Object.keys(DATA).map(k=>k.split('|')[i]))];
function group(el,idx,field){
  document.getElementById(el).innerHTML=uniq(idx).map(v=>
    `<button data-v="${v}">${field==='isa'?ISA_LABEL[v]||v:v}</button>`).join('');
  document.querySelectorAll(`#${el} button`).forEach(b=>
    b.onclick=()=>{sel[field]=b.dataset.v;draw()});
}
group('ctl-isa',0,'isa'); group('ctl-variant',1,'variant'); group('ctl-vector',2,'vector');
document.getElementById('lg').innerHTML=Object.entries(NAMES).map(([k,v])=>
  `<span><i class=sw style="background:${COLORS[k]}"></i>${v}</span>`).join('')
  +`<span style="color:#5c6b74">&nbsp;&mdash; exploitable columns are marked full-height so they survive downscaling</span>`;
function draw(){
  const key=`${sel.isa}|${sel.variant}|${sel.vector}`;
  const d=DATA[key]; if(!d) return;
  const W=d.span, H=4, S=Math.max(1,Math.floor(1600/W));
  c.width=W*S; c.height=H*14;
  x.fillStyle='#0a0e12'; x.fillRect(0,0,c.width,c.height);
  // OK is the background: absent cells are OK (see the encoding note in
  // heatmap.py), so paint the whole field first and overdraw the exceptions.
  x.fillStyle=COLORS[0];
  for(let k=0;k<H;k++) x.fillRect(0,k*14,W*S,13);
  for(const [t,k,o] of d.cells){
    x.fillStyle=COLORS[o];
    x.fillRect(t*S,(k-1)*14,S,13);
  }
  // Exploitable sites are drawn again as full-height markers, with a minimum
  // width, because they are the rarest and most important cells on the plot:
  // 2 columns out of 8,119 vanish when the canvas is scaled to fit. The marker
  // is deliberately a marker, not a widened cell -- it flags the column
  // without misrepresenting how many instructions are affected.
  const MIN=Math.max(S,Math.ceil(W/400));
  x.fillStyle=COLORS[4];
  for(const [t,k,o] of d.cells){
    if(o===4||o===5) x.fillRect(t*S,0,MIN,c.height);
  }
  for(const [el,field] of [['ctl-isa','isa'],['ctl-variant','variant'],['ctl-vector','vector']])
    document.querySelectorAll(`#${el} button`).forEach(b=>
      b.classList.toggle('on',b.dataset.v===sel[field]));
  document.getElementById('sub').innerHTML=
    `${ISA_LABEL[d.isa]||d.isa} secure boot &middot; instruction-skip campaign &middot; `+
    `each column = one instruction in the golden trace, each row = skip width k`;
  const ex=d.counts.SEC_BYPASS+d.counts.SAFETY_VIOLATION;
  document.getElementById('st').innerHTML=
    `golden trace <b>${d.golden}</b> instrs &middot; swept first <b>${d.span}</b> &middot; `+
    `<b>${d.total.toLocaleString()}</b> experiments at <b>${d.rate.toLocaleString()}</b> runs/s<br>`+
    Object.entries(d.counts).map(([k,v])=>`${k} <b>${v}</b>`).join(' &middot; ')+
    `<br>exploitable sites: <b>${ex}</b>`+
    (()=>{ // same variant+vector on the other architecture, for contrast
      const other=sel.isa==='cm3'?'rv32':'cm3';
      const o=DATA[`${other}|${sel.variant}|${sel.vector}`];
      if(!o) return '';
      const oex=o.counts.SEC_BYPASS+o.counts.SAFETY_VIOLATION;
      return `<br><span style="color:#5c6b74">same build on ${ISA_LABEL[other]}: `+
             `<b>${oex}</b> exploitable over ${o.span} swept instrs `+
             `(golden ${o.golden})</span>`;
    })();
  c.onmousemove=e=>{
    const r=c.getBoundingClientRect();
    const t=Math.floor((e.clientX-r.left)/r.width*W), k=Math.floor((e.clientY-r.top)/r.height*H)+1;
    if(t<0||t>=W||k<1||k>H){tip.style.opacity=0;return;}
    const hit=d.cells.find(z=>z[0]===t&&z[1]===k);
    const o=hit?hit[2]:0;            // absent == OK
    const fn=d.fns[d.fcol[t]]||'?';
    tip.style.opacity=1;
    tip.style.left=(e.clientX+14)+'px'; tip.style.top=(e.clientY+14)+'px';
    tip.innerHTML=`instr ${t} &middot; skip k=${k}<br>${fn}()<br><b>${NAMES[o]}</b>`;
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
