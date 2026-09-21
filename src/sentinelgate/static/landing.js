const stages=[
  {verdict:'Inspecting',control:'Identity',log:'Verifying signed agent identity…',signal:''},
  {verdict:'Inspecting',control:'Field lineage',log:'Following customer-data taint into /body…',signal:''},
  {verdict:'Denied',control:'Sink policy',log:'Blocked: customer-data cannot flow to external email.',signal:'deny'},
  {verdict:'Allowed',control:'Least privilege',log:'Safe knowledge search passed all controls.',signal:'allow'}
];
let stage=0;
const verdict=document.getElementById('demo-verdict');
const control=document.getElementById('demo-control');
const log=document.getElementById('demo-log');
const signal=document.getElementById('demo-signal');
function rotate(){const next=stages[stage++%stages.length];verdict.textContent=next.verdict;control.textContent=next.control;log.textContent=next.log;signal.className=`signal ${next.signal}`;}
rotate();
if(!matchMedia('(prefers-reduced-motion: reduce)').matches)setInterval(rotate,2200);
