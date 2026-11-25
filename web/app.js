const $=id=>document.getElementById(id);
let state;
async function api(path, data) {
  const response=await fetch(path,data===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
  const result=await response.json();
  if(!response.ok) throw Error(result.error || 'Request failed');
  return result;
}
const pretty=x=>JSON.stringify(x,null,2);
function selectScenario() {
  const {agent,tool,args}=state.scenarios[Number($('scenario').value)];
  $('request').value=pretty({agent,tool,args});
}
async function refresh(initial=false) {
  state=await api('/api/state');
  const events=state.audit.events;
  const counts={allow:0,deny:0,approval:0};
  for(const e of events) if(Object.hasOwn(counts,e.decision)) counts[e.decision]++;
  $('total').textContent=counts.allow+counts.deny+counts.approval;
  $('allowed').textContent=counts.allow;$('denied').textContent=counts.deny;$('approval').textContent=counts.approval;
  $('integrity').textContent=state.verified?'Retained hash chain verified':'Hash chain verification failed';
  $('events').replaceChildren();
  for(const e of [...events].reverse()) {
    const row=document.createElement('tr');
    for(const [i,value] of [e.time.slice(11,19),e.agent,e.tool,e.decision,e.reason,e.rule??'—'].entries()) {
      const cell=document.createElement('td');cell.textContent=value;if(i===3)cell.className=e.decision;row.append(cell);
    }
    $('events').append(row);
  }
  if(initial) {
    $('policy').value=pretty(state.policy);
    state.scenarios.forEach((s,i)=>$('scenario').add(new Option(s.label,String(i))));
    selectScenario();
  }
}
let busy=false;
async function action(fn) {
  if(busy)return;
  busy=true;$('error').textContent='';
  const buttons=[...document.querySelectorAll('button')];buttons.forEach(b=>b.disabled=true);
  try{await fn();}catch(e){$('error').textContent=e.message;}finally{busy=false;buttons.forEach(b=>b.disabled=false);}
}
$('scenario').addEventListener('change',selectScenario);
$('invoke').addEventListener('click',()=>action(async()=>{
  $('result').textContent=pretty(await api('/api/invoke',JSON.parse($('request').value)));await refresh();
}));
$('suite').addEventListener('click',()=>action(async()=>{
  const results=[];
  for(const {label,agent,tool,args} of state.scenarios) results.push({label,...await api('/api/invoke',{agent,tool,args})});
  $('result').textContent=pretty(results);await refresh();
}));
$('save').addEventListener('click',()=>action(async()=>{
  $('policyStatus').textContent='';await api('/api/policy',JSON.parse($('policy').value));$('policyStatus').textContent='Applied';await refresh();
}));
$('export').addEventListener('click',()=>action(async()=>{
  await refresh();const url=URL.createObjectURL(new Blob([pretty(state.audit)],{type:'application/json'}));
  const a=document.createElement('a');a.href=url;a.download='agentguard-audit.json';a.click();URL.revokeObjectURL(url);
}));
action(()=>refresh(true));
