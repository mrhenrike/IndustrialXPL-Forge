"""FastAPI web apps for world view and HMIs.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 1.0.0
"""

from __future__ import annotations

from typing import Dict, List

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from .state import SharedPlantState


WORLD_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>VirtualPlants OT - Bottle Filling World</title>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate"/>
  <meta http-equiv="Pragma" content="no-cache"/>
  <meta http-equiv="Expires" content="0"/>
  <style>
    body{font-family:Arial,sans-serif;background:#f4f7fb;margin:16px;color:#1f2937}
    h1{margin:0 0 4px 0}.sub{margin:0 0 14px 0;color:#0284c7}
    .card{background:#fff;border:1px solid #d9e2ec;border-radius:10px;padding:12px;margin-bottom:12px}
    #world{width:100%;max-width:980px;height:360px;border:1px solid #d9e2ec;border-radius:8px;background:#fff}
    .buttons{display:flex;gap:10px;margin-top:8px}
    button{border:0;border-radius:8px;padding:10px 14px;cursor:pointer;color:#fff;font-weight:bold}
    .run{background:#16a34a}.stop{background:#dc2626}.reset{background:#0284c7}
  </style>
</head>
<body>
  <h1>VirtualPlants OT</h1>
  <p class="sub">Planta/Processo - Física visual</p>
  <div class="card">
    <canvas id="world" width="980" height="360"></canvas>
    <div class="buttons">
      <button class="run" onclick="sendCommand('run')">Start</button>
      <button class="stop" onclick="sendCommand('stop')">Stop</button>
      <button class="reset" onclick="sendCommand('reset')">Reset</button>
    </div>
  </div>
<script>
const spillVisual={last:0,belt:0,floor:0,splash:0};
async function sendCommand(command,payload={}){
  await fetch('/api/command',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({command,...payload})});
  if(command==='reset'){
    spillVisual.last=0;spillVisual.belt=0;spillVisual.floor=0;spillVisual.splash=0;
  }
}
function drawBottle(ctx,x,floorY,fill,status){
  const bodyHalf=16, neckHalf=6, top=floorY-110, neckBottom=floorY-88, shoulderY=floorY-80, bottom=floorY-4;
  const clipped=Math.max(0,Math.min(fill,1));
  ctx.save();ctx.beginPath();
  ctx.moveTo(x-neckHalf,top);ctx.lineTo(x+neckHalf,top);ctx.lineTo(x+neckHalf,neckBottom);
  ctx.quadraticCurveTo(x+bodyHalf,shoulderY-2,x+bodyHalf,shoulderY+4);ctx.lineTo(x+bodyHalf,bottom);
  ctx.lineTo(x-bodyHalf,bottom);ctx.lineTo(x-bodyHalf,shoulderY+4);ctx.quadraticCurveTo(x-bodyHalf,shoulderY-2,x-neckHalf,neckBottom);
  ctx.closePath();ctx.clip();
  const liquidHeight=clipped*(bottom-shoulderY);
  if(liquidHeight>0){ctx.fillStyle='#2563eb';ctx.fillRect(x-bodyHalf+1,bottom-liquidHeight,(bodyHalf*2)-2,liquidHeight);}
  ctx.restore();
  ctx.strokeStyle='#1d4ed8';ctx.stroke();
  if(status==='broken'){
    ctx.strokeStyle='#dc2626';ctx.beginPath();ctx.moveTo(x-14,floorY-70);ctx.lineTo(x+14,floorY-18);ctx.stroke();
    ctx.beginPath();ctx.moveTo(x+14,floorY-70);ctx.lineTo(x-14,floorY-18);ctx.stroke();
  }else if(status==='fallen'){
    ctx.strokeStyle='#ea580c';ctx.beginPath();ctx.moveTo(x-18,floorY-8);ctx.lineTo(x+16,floorY-26);ctx.stroke();
  }
}
function draw(state){
  const c=document.getElementById('world');const ctx=c.getContext('2d');
  const w=c.width,h=c.height,floorY=h-42;
  ctx.clearRect(0,0,w,h);ctx.fillStyle='#fff';ctx.fillRect(0,0,w,h);
  const nozzleX=Math.floor(w*state.nozzle_position);
  if(spillVisual.belt>0){
    const spread=Math.min(w*0.95, 28 + spillVisual.belt*0.82);
    const left=Math.max(0,nozzleX-(spread*0.58));
    ctx.fillStyle='rgba(37,99,235,0.26)';ctx.fillRect(left,floorY-9,spread,9);
    ctx.fillStyle='rgba(37,99,235,0.22)';ctx.fillRect(left+8,floorY+14,Math.max(0,spread-16),6);
  }
  if(spillVisual.floor>0){
    const plume=Math.min(130, 10 + spillVisual.floor*0.36);
    for(let i=0;i<Math.min(65,10+Math.floor(spillVisual.splash*0.09));i++){
      const dx=(Math.random()*2-1)*plume;const dy=Math.random()*13;
      ctx.fillStyle='rgba(37,99,235,0.35)';ctx.fillRect(nozzleX+dx,floorY-dy,2,2);
    }
  }
  ctx.fillStyle='#000';ctx.fillRect(0,floorY,w,22);
  ctx.fillStyle='#111827';ctx.fillRect(nozzleX-8,92,16,32);ctx.fillRect(nozzleX-2,124,4,12);
  if(Array.isArray(state.bottles)){for(const b of state.bottles){drawBottle(ctx,Math.floor(w*b.x),floorY,Number(b.fill||0),String(b.status||'normal'));}}
  if(state.nozzle_open){
    const startY=136,endY=floorY-4;
    for(let i=0;i<24;i++){
      const t=Math.random();const x=nozzleX+(Math.random()*2-1);const y=Math.min(endY,startY+((endY-startY)*t));
      ctx.fillStyle='#2563eb';ctx.fillRect(x,y,2,2);
    }
  }
}
async function refreshState(){
  const s=await (await fetch('/api/state',{cache:'no-store'})).json();
  const currentSpill=Number(s.spill_count||0);
  if(currentSpill < spillVisual.last){
    spillVisual.belt=0;spillVisual.floor=0;spillVisual.splash=0;
  }
  const delta=Math.max(0, currentSpill-spillVisual.last);
  spillVisual.last=currentSpill;
  spillVisual.belt=Math.min(1100, spillVisual.belt + delta);
  spillVisual.floor=Math.min(820, spillVisual.floor + Math.max(0,delta*0.45));
  spillVisual.splash=Math.min(1400, spillVisual.splash + delta*2);
  spillVisual.belt*=0.992;spillVisual.floor*=0.989;spillVisual.splash*=0.985;
  draw(s);
}
setInterval(refreshState,50);refreshState();
</script>
</body>
</html>
"""


HMI_BASE_STYLE = """
body{font-family:Arial,sans-serif;background:#dfe3ee;margin:16px;color:#111827}
h1{margin:0 0 4px 0}.sub{margin:0 0 10px 0;color:#1e3a8a}
.layout{display:grid;grid-template-columns:1fr 390px;gap:12px;max-width:1380px}
.card{background:#f7f7f7;border:1px solid #b8c2d1;border-radius:8px;padding:10px}
#hmi{width:100%;max-width:900px;height:460px;border:1px solid #a8b3c5;border-radius:8px;background:#ececec}
.buttons{display:flex;gap:10px}
button{border:0;border-radius:8px;padding:10px 15px;cursor:pointer;color:#fff;font-weight:bold}
.run{background:#16a34a}.stop{background:#dc2626}.reset{background:#0284c7}
.io{display:grid;grid-template-columns:180px 1fr;gap:8px;font-size:14px}
.lamp{display:inline-block;width:13px;height:13px;border-radius:50%;margin-right:8px;border:1px solid #374151}
.on{background:#22c55e}.off{background:#ef4444}
.counter{display:grid;grid-template-columns:1fr auto;gap:8px;margin-top:8px}
.charts{margin-top:10px} #trend{width:100%;height:120px;border:1px solid #c3ccdb;border-radius:6px;background:#fff}
.alert-box{margin-top:8px;background:#fff5f5;border:1px solid #fecaca;border-radius:6px;padding:6px;font-size:12px;color:#991b1b;min-height:42px}
.regs{display:grid;grid-template-columns:1fr;gap:8px;margin-top:10px}
pre{margin:0;background:#0f172a;color:#e5e7eb;padding:8px;border-radius:6px;font-size:11px;line-height:1.2;min-height:136px}
.legend{margin-top:10px;background:#fff;border:1px solid #cbd5e1;border-radius:6px;padding:8px;max-height:230px;overflow:auto}
.legend h4{margin:0 0 6px 0;font-size:13px}
.legend-line{font-size:11px;line-height:1.3;border-bottom:1px dashed #e5e7eb;padding:2px 0}
.contam{margin-top:10px;background:#fff;border:1px solid #cbd5e1;border-radius:6px;padding:8px}
.contam-title{font-size:12px;font-weight:bold;margin-bottom:6px}
.zones{display:grid;grid-template-columns:repeat(6,1fr);gap:4px}
.zone{height:14px;border-radius:4px;border:1px solid #94a3b8;background:#e2e8f0}
.contam-legend{margin-top:6px;font-size:11px;color:#334155;display:flex;gap:10px;flex-wrap:wrap}
.pill{padding:1px 6px;border-radius:999px;font-size:10px;color:#fff}
.ok{background:#16a34a}.warn{background:#f59e0b}.alarm{background:#dc2626}
"""


HMI_COMMON_SCRIPT = """
const speedHistory=[];const spillHistory=[];const spillVisualHmi={last:0,belt:0,floor:0,splash:0,wetZones:[0,0,0,0,0,0]};
async function sendCommand(command,payload={}){
  await fetch('/api/command',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({command,...payload})});
  if(command==='reset'){
    spillVisualHmi.last=0;spillVisualHmi.belt=0;spillVisualHmi.floor=0;spillVisualHmi.splash=0;
    for(let i=0;i<spillVisualHmi.wetZones.length;i++){spillVisualHmi.wetZones[i]=0;}
    for(let i=0;i<6;i++){
      const z=document.getElementById('zone'+(i+1));
      if(z){z.style.background='#e2e8f0';}
    }
    const contamLabel=document.getElementById('contamLabel');
    if(contamLabel){contamLabel.textContent='Contamination: NORMAL | WetAvg=0.0%';}
  }
}
function setLamp(id,on){const el=document.getElementById(id);el.classList.remove('on','off');el.classList.add(on?'on':'off');}
function drawTrend(){
  const c=document.getElementById('trend');const ctx=c.getContext('2d');const w=c.width,h=c.height;
  ctx.clearRect(0,0,w,h);ctx.fillStyle='#fff';ctx.fillRect(0,0,w,h);ctx.strokeStyle='#d1d5db';ctx.strokeRect(0,0,w,h);
  if(speedHistory.length<2){return;}const maxSpill=Math.max(...spillHistory,1);const maxSpeed=0.16;
  ctx.strokeStyle='#2563eb';ctx.beginPath();for(let i=0;i<speedHistory.length;i++){const x=(i/(speedHistory.length-1))*(w-10)+5;const y=h-5-((speedHistory[i]/maxSpeed)*(h-10));if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);}ctx.stroke();
  ctx.strokeStyle='#dc2626';ctx.beginPath();for(let i=0;i<spillHistory.length;i++){const x=(i/(spillHistory.length-1))*(w-10)+5;const y=h-5-((spillHistory[i]/maxSpill)*(h-10));if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);}ctx.stroke();
}
function drawBottle(ctx,x,floorY,fill,status){
  const bodyHalf=18, neckHalf=7, top=floorY-128, neckBottom=floorY-104, shoulderY=floorY-95, bottom=floorY-5;
  const clipped=Math.max(0,Math.min(fill,1));ctx.save();ctx.beginPath();
  ctx.moveTo(x-neckHalf,top);ctx.lineTo(x+neckHalf,top);ctx.lineTo(x+neckHalf,neckBottom);ctx.quadraticCurveTo(x+bodyHalf,shoulderY-3,x+bodyHalf,shoulderY+4);
  ctx.lineTo(x+bodyHalf,bottom);ctx.lineTo(x-bodyHalf,bottom);ctx.lineTo(x-bodyHalf,shoulderY+4);ctx.quadraticCurveTo(x-bodyHalf,shoulderY-3,x-neckHalf,neckBottom);ctx.closePath();ctx.clip();
  const h=clipped*(bottom-shoulderY);if(h>0){ctx.fillStyle='#2563eb';ctx.fillRect(x-bodyHalf+1,bottom-h,(bodyHalf*2)-2,h);}ctx.restore();ctx.strokeStyle='#1d4ed8';ctx.stroke();
  if(status==='broken'){ctx.strokeStyle='#dc2626';ctx.beginPath();ctx.moveTo(x-14,floorY-82);ctx.lineTo(x+14,floorY-20);ctx.stroke();ctx.beginPath();ctx.moveTo(x+14,floorY-82);ctx.lineTo(x-14,floorY-20);ctx.stroke();}
  if(status==='fallen'){ctx.strokeStyle='#ea580c';ctx.beginPath();ctx.moveTo(x-20,floorY-12);ctx.lineTo(x+18,floorY-30);ctx.stroke();}
}
function drawHmi(state){
  const c=document.getElementById('hmi');const ctx=c.getContext('2d');const w=c.width,h=c.height,floorY=h-64;
  ctx.clearRect(0,0,w,h);ctx.fillStyle='#ececec';ctx.fillRect(0,0,w,h);
  const nozzleX=Math.floor(w*state.nozzle_position);ctx.fillStyle='#9ca3af';ctx.fillRect(nozzleX+90,58,110,130);
  ctx.beginPath();ctx.moveTo(nozzleX+90,188);ctx.lineTo(nozzleX+200,188);ctx.lineTo(nozzleX+145,220);ctx.closePath();ctx.fill();
  ctx.strokeStyle='#3b82f6';ctx.lineWidth=6;ctx.beginPath();ctx.moveTo(nozzleX+90,208);ctx.lineTo(nozzleX+8,208);ctx.lineTo(nozzleX+8,234);ctx.stroke();
  ctx.fillStyle='#111827';ctx.fillRect(nozzleX-8,234,16,26);ctx.fillRect(nozzleX-2,260,4,16);
  if(spillVisualHmi.belt>0){
    const spread=Math.min(w*0.82, 24 + spillVisualHmi.belt*0.66);
    const left=Math.max(16, nozzleX - (spread*0.55));
    ctx.fillStyle='rgba(37,99,235,0.22)';ctx.fillRect(left,floorY-10,spread,10);
    ctx.fillStyle='rgba(37,99,235,0.22)';ctx.fillRect(left+5,floorY+10,Math.max(0,spread-10),6);
  }
  ctx.fillStyle='#7c2d12';ctx.fillRect(26,floorY,w-52,10);ctx.fillStyle='#111827';ctx.fillRect(26,floorY+10,w-52,14);
  if(Array.isArray(state.bottles)){for(const b of state.bottles){const bx=Math.floor(w*b.x);const st=String(b.status||'normal');drawBottle(ctx,bx,floorY,Number(b.fill||0),st);if(st==='broken'||st==='fallen'){ctx.fillStyle='rgba(37,99,235,0.35)';ctx.fillRect(bx-22,floorY-7,44,7);}}}
  if(spillVisualHmi.floor>0){
    const plume=Math.min(100, 8 + spillVisualHmi.floor*0.30);
    for(let i=0;i<Math.min(55, 8+Math.floor(spillVisualHmi.splash*0.07));i++){const dx=(Math.random()*2-1)*plume;const dy=Math.random()*11;ctx.fillStyle='rgba(37,99,235,0.35)';ctx.fillRect(nozzleX+dx,floorY-dy,2,2);}
  }
  const zoneW=(w-52)/6;
  for(let i=0;i<6;i++){
    const wet=Math.max(0,Math.min(1,spillVisualHmi.wetZones[i]||0));
    if(wet<=0){continue;}
    const alpha=0.12+(wet*0.45);
    ctx.fillStyle='rgba(37,99,235,'+alpha.toFixed(3)+')';
    ctx.fillRect(26+(i*zoneW),floorY-22,zoneW-1,12);
  }
}
function fmt(prefix,arr){let out='';for(let i=0;i<arr.length;i++){const n=String(i+1).padStart(4,'0');out += prefix+'['+n+']='+String(arr[i])+'\\n';}return out;}
async function refreshRegisters(){
  const reg=await (await fetch('/api/registers',{cache:'no-store'})).json();
  const hr=document.getElementById('hr');if(hr){hr.textContent='HOLDING REGISTERS\\n'+fmt('HR',reg.holding_registers||[]);}
}
async function refreshLegend(){
  const box=document.getElementById('legendBox');if(!box){return;}
  const data=await (await fetch('/api/register_legend',{cache:'no-store'})).json();
  const lines=[];
  lines.push('<h4>HOLDING REGISTERS</h4>');
  for(const item of data.holding_registers||[]){
    lines.push('<div class="legend-line"><strong>'+item.id+'</strong> ['+item.access+'] ['+item.kind+'] - '+item.description+'</div>');
  }
  box.innerHTML=lines.join('');
}
async function refreshState(){
  const s=await (await fetch('/api/state',{cache:'no-store'})).json();
  const currentSpill=Number(s.spill_count||0);
  if(currentSpill < spillVisualHmi.last){
    spillVisualHmi.belt=0;spillVisualHmi.floor=0;spillVisualHmi.splash=0;
    for(let i=0;i<spillVisualHmi.wetZones.length;i++){spillVisualHmi.wetZones[i]=0;}
  }
  const delta=Math.max(0, currentSpill-spillVisualHmi.last);
  spillVisualHmi.last=currentSpill;
  spillVisualHmi.belt=Math.min(900, spillVisualHmi.belt + delta);
  spillVisualHmi.floor=Math.min(700, spillVisualHmi.floor + delta*0.4);
  spillVisualHmi.splash=Math.min(1000, spillVisualHmi.splash + delta*1.8);
  spillVisualHmi.belt*=0.992;spillVisualHmi.floor*=0.989;spillVisualHmi.splash*=0.985;
  for(let i=0;i<spillVisualHmi.wetZones.length;i++){spillVisualHmi.wetZones[i]*=0.994;}
  const zoneIndex=Math.max(0,Math.min(5,Math.floor(Number(s.nozzle_position||0.52)*6)));
  const localWet=(delta/300.0);
  spillVisualHmi.wetZones[zoneIndex]=Math.min(1.0,spillVisualHmi.wetZones[zoneIndex]+localWet);
  if(zoneIndex>0){spillVisualHmi.wetZones[zoneIndex-1]=Math.min(1.0,spillVisualHmi.wetZones[zoneIndex-1]+(localWet*0.32));}
  if(zoneIndex<5){spillVisualHmi.wetZones[zoneIndex+1]=Math.min(1.0,spillVisualHmi.wetZones[zoneIndex+1]+(localWet*0.32));}
  document.getElementById('status').textContent=s.status;document.getElementById('bottle').textContent=s.bottle_in_position?'YES':'NO';
  document.getElementById('nozzle').textContent=s.nozzle_open?'OPEN':'CLOSED';document.getElementById('motor').textContent=s.motor_on?'ON':'OFF';
  document.getElementById('level').textContent=s.level_hit?'YES':'NO';document.getElementById('produced').textContent=s.produced_count;
  document.getElementById('spill').textContent=s.spill_count;document.getElementById('collisions').textContent=s.collisions_count||0;
  document.getElementById('broken').textContent=s.broken_count||0;document.getElementById('fallen').textContent=s.fallen_count||0;
  document.getElementById('speed').textContent=Number(s.conveyor_speed||0.04).toFixed(3)+' u/s';
  document.getElementById('alertsBox').textContent=(s.alerts&&s.alerts.length)?s.alerts.join(' | '):'No active alerts';
  const contamLabel=document.getElementById('contamLabel');
  if(contamLabel){
    const wetAvg=(spillVisualHmi.wetZones.reduce((a,b)=>a+b,0)/spillVisualHmi.wetZones.length);
    let statusTxt='NORMAL';
    if(Number(s.spill_count||0)>1400 || wetAvg>0.75){statusTxt='CRITICO';}
    else if(Number(s.spill_count||0)>900 || wetAvg>0.45){statusTxt='ALTO';}
    else if(Number(s.spill_count||0)>600 || wetAvg>0.22){statusTxt='MODERADO';}
    contamLabel.textContent='Contamination: '+statusTxt+' | WetAvg='+(wetAvg*100).toFixed(1)+'%';
  }
  for(let i=0;i<6;i++){
    const z=document.getElementById('zone'+(i+1));
    if(!z){continue;}
    const wet=Math.max(0,Math.min(1,spillVisualHmi.wetZones[i]||0));
    const r=Math.floor(34 + (220*wet));
    const g=Math.floor(197 - (130*wet));
    const b=Math.floor(94 - (74*wet));
    z.style.background='rgb('+r+','+g+','+Math.max(20,b)+')';
    z.title='Zone '+(i+1)+' wet='+(wet*100).toFixed(1)+'%';
  }
  setLamp('lampBottle',!!s.bottle_in_position);setLamp('lampLevel',!!s.level_hit);setLamp('lampNozzle',!!s.nozzle_open);setLamp('lampMotor',!!s.motor_on);
  speedHistory.push(Number(s.conveyor_speed||0.04));spillHistory.push(Number(s.spill_count||0));if(speedHistory.length>70){speedHistory.shift();spillHistory.shift();}
  drawTrend();drawHmi(s);
}
"""


HMI_MONITOR_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>VirtualPlants OT - Bottle Filling HMI Monitor</title>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate"/>
  <meta http-equiv="Pragma" content="no-cache"/>
  <meta http-equiv="Expires" content="0"/>
  <style>""" + HMI_BASE_STYLE + """</style>
</head>
<body>
  <h1>VirtualPlants OT</h1>
  <p class="sub">HMI/SCADA Monitor - operação normal (sem sabotagem)</p>
  <div class="layout">
    <div class="card"><canvas id="hmi" width="900" height="460"></canvas></div>
    <div class="card">
      <div class="buttons">
        <button class="run" onclick="sendCommand('run')">START</button>
        <button class="stop" onclick="sendCommand('stop')">STOP</button>
        <button class="reset" onclick="sendCommand('reset')">RESET</button>
      </div>
      <div class="counter">
        <div><strong>PV COUNTER</strong></div><div id="produced">0</div>
        <div><strong>SPILL COUNTER (ml)</strong></div><div id="spill">0</div>
      </div>
      <hr/>
      <div class="io">
        <div>Process status</div><div id="status">-</div>
        <div>Bottle sensor</div><div><span id="lampBottle" class="lamp off"></span><span id="bottle">NO</span></div>
        <div>Level sensor</div><div><span id="lampLevel" class="lamp off"></span><span id="level">NO</span></div>
        <div>Valve liquid</div><div><span id="lampNozzle" class="lamp off"></span><span id="nozzle">CLOSED</span></div>
        <div>Conveyor motor</div><div><span id="lampMotor" class="lamp off"></span><span id="motor">OFF</span></div>
        <div>Conveyor speed</div><div id="speed">0.040 u/s</div>
        <div>Collisions</div><div id="collisions">0</div>
        <div>Broken/Fallen</div><div><span id="broken">0</span> / <span id="fallen">0</span></div>
      </div>
      <div class="charts"><canvas id="trend" width="360" height="120"></canvas></div>
      <div class="contam">
        <div class="contam-title">Mapa de Contaminação da Esteira</div>
        <div class="zones">
          <div id="zone1" class="zone"></div><div id="zone2" class="zone"></div><div id="zone3" class="zone"></div>
          <div id="zone4" class="zone"></div><div id="zone5" class="zone"></div><div id="zone6" class="zone"></div>
        </div>
        <div id="contamLabel" style="margin-top:6px;font-size:11px;color:#0f172a">Contamination: NORMAL | WetAvg=0.0%</div>
        <div class="contam-legend">
          <span class="pill ok">NORMAL</span><span class="pill warn">ALTO</span><span class="pill alarm">CRITICO</span>
        </div>
      </div>
      <div id="alertsBox" class="alert-box">No active alerts</div>
    </div>
  </div>
<script>""" + HMI_COMMON_SCRIPT + """
setInterval(refreshState,100);refreshState();
</script>
</body>
</html>
"""


HMI_CONTROL_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>VirtualPlants OT - Bottle Filling HMI Control</title>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate"/>
  <meta http-equiv="Pragma" content="no-cache"/>
  <meta http-equiv="Expires" content="0"/>
  <style>""" + HMI_BASE_STYLE + """</style>
</head>
<body>
  <h1>VirtualPlants OT</h1>
  <p class="sub">HMI Controle/Sabotagem + Console OT</p>
  <div class="layout">
    <div class="card"><canvas id="hmi" width="900" height="460"></canvas></div>
    <div class="card">
      <div class="buttons">
        <button class="run" onclick="sendCommand('run')">START</button>
        <button class="stop" onclick="sendCommand('stop')">STOP</button>
        <button class="reset" onclick="sendCommand('reset')">RESET</button>
      </div>
      <div class="counter">
        <div><strong>PV COUNTER</strong></div><div id="produced">0</div>
        <div><strong>SPILL COUNTER (ml)</strong></div><div id="spill">0</div>
      </div>
      <div style="margin-top:8px;padding:8px;border:1px solid #cbd5e1;border-radius:6px;background:#fff">
        <div style="font-size:12px;color:#334155;margin-bottom:6px">
          Manipulação didática de processo: alterar registradores de operação (velocidade, limites e sensores).
        </div>
        <div style="display:flex;gap:8px;align-items:center;margin-top:6px;flex-wrap:wrap">
          <span>Speed</span>
          <input id="speedCtrl" type="range" min="0.04" max="0.16" step="0.002" value="0.04" oninput="sendCommand('speed',{value:Number(this.value)});document.getElementById('speedCtrlValue').textContent=Number(this.value).toFixed(3)"/>
          <span id="speedCtrlValue">0.040</span>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:6px">
          <label>Sensor Min <input id="smin" type="number" step="0.001" min="0.35" max="0.70" value="0.515"/></label>
          <label>Sensor Max <input id="smax" type="number" step="0.001" min="0.36" max="0.72" value="0.525"/></label>
          <label>Fill Limit <input id="flim" type="number" step="0.01" min="0" max="1.30" value="0.92"/></label>
          <label>Sensor Window <input id="swin" type="number" step="0.001" min="0.01" max="0.08" value="0.02"/></label>
        </div>
        <div style="display:flex;gap:8px;margin-top:6px;align-items:center;flex-wrap:wrap">
          <button class="reset" onclick="sendCommand('tuning',{sensor_min:Number(document.getElementById('smin').value),sensor_max:Number(document.getElementById('smax').value),fill_limit:Number(document.getElementById('flim').value),sensor_window:Number(document.getElementById('swin').value)})">APPLY TUNING</button>
          <label><input type="checkbox" id="bottleSensor" checked onchange="sendCommand('bottle_sensor',{enabled:this.checked})"/> Bottle Sensor ON</label>
          <label><input type="checkbox" id="levelSensor" checked onchange="sendCommand('level_sensor',{enabled:this.checked})"/> Level Sensor ON</label>
        </div>
      </div>
      <hr/>
      <div class="io">
        <div>Process status</div><div id="status">-</div>
        <div>Bottle sensor</div><div><span id="lampBottle" class="lamp off"></span><span id="bottle">NO</span></div>
        <div>Level sensor</div><div><span id="lampLevel" class="lamp off"></span><span id="level">NO</span></div>
        <div>Valve liquid</div><div><span id="lampNozzle" class="lamp off"></span><span id="nozzle">CLOSED</span></div>
        <div>Conveyor motor</div><div><span id="lampMotor" class="lamp off"></span><span id="motor">OFF</span></div>
        <div>Conveyor speed</div><div id="speed">0.040 u/s</div>
        <div>Collisions</div><div id="collisions">0</div>
        <div>Broken/Fallen</div><div><span id="broken">0</span> / <span id="fallen">0</span></div>
      </div>
      <div class="charts"><canvas id="trend" width="360" height="120"></canvas></div>
      <div class="contam">
        <div class="contam-title">Mapa de Contaminação da Esteira</div>
        <div class="zones">
          <div id="zone1" class="zone"></div><div id="zone2" class="zone"></div><div id="zone3" class="zone"></div>
          <div id="zone4" class="zone"></div><div id="zone5" class="zone"></div><div id="zone6" class="zone"></div>
        </div>
        <div id="contamLabel" style="margin-top:6px;font-size:11px;color:#0f172a">Contamination: NORMAL | WetAvg=0.0%</div>
        <div class="contam-legend">
          <span class="pill ok">NORMAL</span><span class="pill warn">ALTO</span><span class="pill alarm">CRITICO</span>
        </div>
      </div>
      <div id="alertsBox" class="alert-box">No active alerts</div>
      <div class="regs"><pre id="hr"></pre></div>
      <div class="legend"><div id="legendBox"></div></div>
    </div>
  </div>
<script>""" + HMI_COMMON_SCRIPT + """
setInterval(refreshState,100);setInterval(refreshRegisters,250);refreshState();refreshRegisters();refreshLegend();
</script>
</body>
</html>
"""


def _command_handler(shared_state: SharedPlantState, payload: Dict[str, object]) -> Dict[str, object]:
    """Apply command payload to simulation state."""
    command = str(payload.get("command", "")).strip().lower()
    allowed = {
        "run",
        "stop",
        "reset",
        "speed",
        "tuning",
        "level_sensor",
        "bottle_sensor",
    }
    if command not in allowed:
        raise HTTPException(status_code=400, detail="invalid_command")

    if command == "run":
        shared_state.set_run(True)
    elif command == "stop":
        shared_state.set_run(False)
    elif command == "reset":
        shared_state.request_reset()
    elif command == "speed":
        value = float(payload.get("value", 0.04))
        shared_state.patch(conveyor_speed=max(0.04, min(0.16, value)))
    elif command == "level_sensor":
        shared_state.patch(level_sensor_enabled=bool(payload.get("enabled", True)))
    elif command == "bottle_sensor":
        shared_state.patch(bottle_sensor_enabled=bool(payload.get("enabled", True)))
    else:
        shared_state.patch(
            sensor_min_position=max(0.35, min(0.70, float(payload.get("sensor_min", 0.515)))),
            sensor_max_position=max(0.36, min(0.72, float(payload.get("sensor_max", 0.525)))),
            fill_level_limit=max(0.0, min(1.30, float(payload.get("fill_limit", 0.92)))),
            sensor_window=max(0.01, min(0.08, float(payload.get("sensor_window", 0.02)))),
        )
    return {"status": "ok", "command": command}


def _build_register_snapshot(state: Dict[str, object]) -> Dict[str, List[int]]:
    """Build OT holding register view from current state."""
    run = 1 if bool(state.get("run_command")) else 0
    bottle_sensor = 1 if bool(state.get("bottle_sensor_enabled")) else 0
    level_sensor = 1 if bool(state.get("level_sensor_enabled")) else 0
    produced = int(state.get("produced_count", 0)) % 65535
    spill = int(state.get("spill_count", 0)) % 65535
    bottle = 1 if bool(state.get("bottle_in_position")) else 0
    level = 1 if bool(state.get("level_hit")) else 0
    nozzle = 1 if bool(state.get("nozzle_open")) else 0
    motor = 1 if bool(state.get("motor_on")) else 0

    def scale(value: float, low: float, high: float) -> int:
        value = max(low, min(high, value))
        return int(round(((value - low) / (high - low)) * 1000.0))

    hr = [
        run,
        0,
        bottle_sensor,
        level_sensor,
        scale(float(state.get("sensor_min_position", 0.515)), 0.35, 0.70),
        scale(float(state.get("sensor_max_position", 0.525)), 0.36, 0.72),
        scale(float(state.get("fill_level_limit", 0.92)), 0.0, 1.30),
        scale(float(state.get("conveyor_speed", 0.04)), 0.04, 0.16),
        scale(float(state.get("bottle_spacing", 0.095)), 0.06, 0.18),
        scale(float(state.get("sensor_window", 0.02)), 0.01, 0.08),
        produced,
        spill,
        bottle,
        level,
        nozzle,
        motor,
    ]
    return {"holding_registers": hr}


def _build_register_legend() -> Dict[str, List[Dict[str, str]]]:
    """Return functional legend for OT holding registers only."""
    hr = [
        {"id": "HR[0001]", "access": "W/R", "kind": "comando", "description": "Run command/state (1=start,0=stop)"},
        {"id": "HR[0002]", "access": "W/R", "kind": "comando", "description": "Reset pulse (write 1 to reset, auto-clear)"},
        {"id": "HR[0003]", "access": "W/R", "kind": "sensor", "description": "Bottle sensor enable (1/0)"},
        {"id": "HR[0004]", "access": "W/R", "kind": "sensor", "description": "Level sensor enable (1/0)"},
        {"id": "HR[0005]", "access": "W/R", "kind": "limite", "description": "Sensor min position (escala 0..1000)"},
        {"id": "HR[0006]", "access": "W/R", "kind": "limite", "description": "Sensor max position (escala 0..1000)"},
        {"id": "HR[0007]", "access": "W/R", "kind": "limite", "description": "Fill limit setpoint (escala 0..1000)"},
        {"id": "HR[0008]", "access": "W/R", "kind": "parametro", "description": "Conveyor speed (escala 0..1000)"},
        {"id": "HR[0009]", "access": "W/R", "kind": "parametro", "description": "Bottle spacing (escala 0..1000)"},
        {"id": "HR[0010]", "access": "W/R", "kind": "parametro", "description": "Sensor window (escala 0..1000)"},
        {"id": "HR[0011]", "access": "W/R", "kind": "contador", "description": "Produced bottles counter"},
        {"id": "HR[0012]", "access": "W/R", "kind": "contador", "description": "Spill counter (ml simulado)"},
        {"id": "HR[0013]", "access": "W/R", "kind": "sensor", "description": "Bottle in position (runtime mirror)"},
        {"id": "HR[0014]", "access": "W/R", "kind": "sensor", "description": "Level reached (runtime mirror)"},
        {"id": "HR[0015]", "access": "W/R", "kind": "atuador", "description": "Nozzle state (runtime mirror)"},
        {"id": "HR[0016]", "access": "W/R", "kind": "atuador", "description": "Conveyor motor state (runtime mirror)"},
    ]
    coils = [
        {"id": "COIL[0001]", "access": "W/R", "kind": "comando", "description": "Run command"},
        {"id": "COIL[0002]", "access": "W/R", "kind": "comando", "description": "Reset pulse"},
        {"id": "COIL[0003]", "access": "W/R", "kind": "sensor", "description": "Bottle sensor enable"},
        {"id": "COIL[0004]", "access": "W/R", "kind": "sensor", "description": "Level sensor enable"},
        {"id": "COIL[0005]", "access": "R", "kind": "atuador", "description": "Motor on (mirror)"},
        {"id": "COIL[0006]", "access": "R", "kind": "atuador", "description": "Nozzle open (mirror)"},
    ]
    discrete = [
        {"id": "DI[0001]", "access": "R", "kind": "sensor", "description": "Bottle in position"},
        {"id": "DI[0002]", "access": "R", "kind": "sensor", "description": "Level hit"},
        {"id": "DI[0003]", "access": "R", "kind": "atuador", "description": "Motor on"},
        {"id": "DI[0004]", "access": "R", "kind": "atuador", "description": "Nozzle open"},
    ]
    ir = [
        {"id": "IR[0001]", "access": "R", "kind": "contador", "description": "Produced count"},
        {"id": "IR[0002]", "access": "R", "kind": "contador", "description": "Spill count"},
        {"id": "IR[0003]", "access": "R", "kind": "processo", "description": "Fill level * 1000"},
        {"id": "IR[0004]", "access": "R", "kind": "parametro", "description": "Conveyor speed scaled 0..1000"},
    ]
    return {
        "holding_registers": hr,
        "coils": coils,
        "discrete_inputs": discrete,
        "input_registers": ir,
    }


def _wire_common_routes(app: FastAPI, shared_state: SharedPlantState, html: str) -> None:
    """Attach shared routes for all web apps."""

    @app.get("/", response_class=HTMLResponse)
    async def root() -> str:
        return html

    @app.get("/api/state")
    async def state() -> Dict[str, object]:
        return shared_state.as_dict()

    @app.get("/api/registers")
    async def registers() -> Dict[str, List[int]]:
        return _build_register_snapshot(shared_state.as_dict())

    @app.get("/api/register_legend")
    async def register_legend() -> Dict[str, List[Dict[str, str]]]:
        return _build_register_legend()

    @app.post("/api/command")
    async def command(payload: Dict[str, object]) -> Dict[str, object]:
        return _command_handler(shared_state, payload)


def create_world_app(shared_state: SharedPlantState) -> FastAPI:
    """Create physics-only world app."""
    app = FastAPI(title="Bottle Filling World", docs_url=None, redoc_url=None)
    _wire_common_routes(app, shared_state, WORLD_HTML)
    return app


def create_hmi_app(shared_state: SharedPlantState) -> FastAPI:
    """Create monitor-only HMI app."""
    app = FastAPI(title="Bottle Filling HMI Monitor", docs_url=None, redoc_url=None)
    _wire_common_routes(app, shared_state, HMI_MONITOR_HTML)
    return app


def create_control_hmi_app(shared_state: SharedPlantState) -> FastAPI:
    """Create control HMI app with sabotage tools."""
    app = FastAPI(title="Bottle Filling HMI Control", docs_url=None, redoc_url=None)
    _wire_common_routes(app, shared_state, HMI_CONTROL_HTML)
    return app
