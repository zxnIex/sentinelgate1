const story = [
  {label:'SOURCE', title:'Untrusted webpage read', packet:'web.content', json:'{"trust":"untrusted","labels":["prompt-injection"]}', reason:'External content is data, not authority.', state:'read'},
  {label:'FIELD LINEAGE', title:'Taint bound to /body', packet:'/body: untrusted', json:'{"/to":[],"/body":["untrusted","prompt-injection"]}', reason:'The harmless recipient remains separate from the influenced body.', state:'taint'},
  {label:'PROPOSED ACTION', title:'External email requested', packet:'send_email', json:'{"to":"external@example.com","body":"…"}', reason:'The agent proposes the call; it has not executed it.', state:'attempt'},
  {label:'DECISION · DENY', title:'Sensitive sink blocked', packet:'DENIED', json:'{"effect":"deny","reason":"FIELD_UNTRUSTED:/body"}', reason:'Policy refuses untrusted content at this outbound sink.', state:'denied'},
  {label:'AUDIT EVIDENCE', title:'Lineage remains inspectable', packet:'trace.recorded', json:'{"source":"web","field":"/body","sink":"send_email"}', reason:'Operators can inspect what flowed where and why it stopped.', state:'audit'}
];
let current = 0;
const steps = [...document.querySelectorAll('#story-steps li')];
const stage = document.querySelector('.story-stage');
function selectStory(index){
  current = Number(index) % story.length;
  const item = story[current];
  steps.forEach((node,i)=>node.classList.toggle('active',i===current));
  document.getElementById('stage-label').textContent=item.label;
  document.getElementById('stage-title').textContent=item.title;
  document.getElementById('flow-packet').textContent=item.packet;
  document.getElementById('stage-json').textContent=item.json;
  document.getElementById('stage-reason').textContent=item.reason;
  stage.dataset.state=item.state;
}
steps.forEach((node,i)=>node.querySelector('button').addEventListener('click',()=>selectStory(i)));
document.getElementById('story-next').addEventListener('click',()=>selectStory(current+1));

const quickButtons=[...document.querySelectorAll('[data-panel]')];
const quickPanels=[...document.querySelectorAll('[data-panel-content]')];
quickButtons.forEach(button=>button.addEventListener('click',()=>{
  const selected=button.dataset.panel;
  quickButtons.forEach(x=>x.classList.toggle('active',x===button));
  quickPanels.forEach(x=>x.hidden=x.dataset.panelContent!==selected);
}));
