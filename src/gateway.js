import {randomUUID,createHash} from 'node:crypto';
import {validatePolicy,AgentGuard} from './guard.js';
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_-]{1,80}$/.test(x);
const plain=x=>x!==null&&typeof x==='object'&&Object.getPrototypeOf(x)===Object.prototype;
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const zero='0'.repeat(64);
const sensitive=/(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:sk|ghp|github_pat)_[A-Za-z0-9_-]{16,}|\bAKIA[A-Z0-9]{16}\b|\bBearer\s+[A-Za-z0-9._~-]{16,})/i;
const argsMatch=(args,schema)=>plain(args)&&Object.keys(args).length===Object.keys(schema).length&&Object.entries(schema).every(([k,s])=>Object.hasOwn(args,k)&&typeof args[k]===s.type&&(s.type!=='string'||args[k].length<=(s.maxLength??256))&&(s.type!=='number'||Number.isFinite(args[k]))&&(!s.values||s.values.includes(args[k])));
const risk={allow:'low',deny:'high',approval:'medium'};
export class Gateway {
  #state;#tools;#store;#clock;#pending=new Map();#active=0;#timeout;#maxConcurrent;#ttl;#failed=false;
  constructor({policy,tools={},store,clock=Date.now,timeoutMs=5000,maxConcurrent=8,approvalTtlMs=120000}) {
    if(!Number.isInteger(timeoutMs)||timeoutMs<1||!Number.isInteger(maxConcurrent)||maxConcurrent<1||!Number.isInteger(approvalTtlMs)||approvalTtlMs<1)throw Error('Invalid gateway limits');
    this.#store=store;this.#clock=clock;this.#timeout=timeoutMs;this.#maxConcurrent=maxConcurrent;this.#ttl=approvalTtlMs;
    this.#tools=new Map(Object.entries(tools));
    if([...this.#tools].some(([k,v])=>!id(k)||typeof v!=='function'))throw Error('Invalid tools');
    this.#state=store?.load({policy:validatePolicy(policy),revision:1,history:[],halted:false,disabled:[],buckets:{},events:[],anchor:zero,totals:{allow:0,deny:0,approval:0,executed:0,error:0,timeout:0}})??{policy:validatePolicy(policy),revision:1,history:[],halted:false,disabled:[],buckets:{},events:[],anchor:zero,totals:{allow:0,deny:0,approval:0,executed:0,error:0,timeout:0}};
    validatePolicy(this.#state.policy);
    if(!AgentGuard.verifyAudit(this.audit()))throw Error('Audit integrity check failed');
  }
  #persist(){if(this.#failed)throw Error('Gateway storage unavailable');try{this.#store?.save(this.#state);}catch(e){this.#failed=true;throw e;}}
  #log(fields){
    const e={id:randomUUID(),time:new Date(this.#clock()).toISOString(),policyVersion:this.#state.policy.version,revision:this.#state.revision,...fields,previousHash:this.#state.events.at(-1)?.hash??this.#state.anchor};
    e.hash=hash(e);this.#state.events.push(e);
    if(Object.hasOwn(this.#state.totals,e.decision))this.#state.totals[e.decision]++;
    if(this.#state.events.length>1000)this.#state.anchor=this.#state.events.shift().hash;
    this.#persist();return e.id;
  }
  audit(){return structuredClone({anchor:this.#state.anchor,events:this.#state.events});}
  get policy(){return structuredClone(this.#state.policy);}
  status(){return {revision:this.#state.revision,halted:this.#state.halted,disabled:[...this.#state.disabled],active:this.#active,healthy:!this.#failed,totals:{...this.#state.totals},tools:[...this.#tools.keys()],pending:this.pending().length};}
  history(){return structuredClone(this.#state.history);}
  setPolicy(policy,expectedRevision,actor='operator'){
    if(expectedRevision!==this.#state.revision)throw Error('Policy revision conflict');
    const next=validatePolicy(policy);
    this.#state.history.push({revision:this.#state.revision,policy:this.#state.policy});if(this.#state.history.length>20)this.#state.history.shift();
    this.#state.policy=next;this.#state.revision++;
    this.#log({agent:actor,tool:'policy_update',decision:'policy_updated',reason:'Policy replaced',rule:null});
    return this.#state.revision;
  }
  rollback(revision,expectedRevision,actor){const old=this.#state.history.find(x=>x.revision===revision);if(!old)throw Error('Revision not retained');return this.setPolicy(old.policy,expectedRevision,actor);}
  halt(value,actor='operator'){if(typeof value!=='boolean')throw Error('Expected boolean');this.#state.halted=value;this.#log({agent:actor,tool:'kill_switch',decision:'control',reason:value?'Gateway halted':'Gateway resumed',rule:null});}
  disable(agent,value,actor='operator'){if(!id(agent)||typeof value!=='boolean')throw Error('Invalid agent control');const s=new Set(this.#state.disabled);if(value)s.add(agent);else s.delete(agent);if(s.size>500)throw Error('Disabled-agent limit reached');this.#state.disabled=[...s];this.#log({agent:actor,tool:'agent_control',decision:'control',reason:value?'Agent disabled':'Agent enabled',target:agent,rule:null});}
  #expire(){for(const [k,p] of this.#pending)if(p.expires<=this.#clock()){this.#pending.delete(k);this.#log({agent:p.agent,tool:p.tool,decision:'approval_expired',reason:'Review expired',rule:null,requestId:k});}}
  pending(){this.#expire();return [...this.#pending].map(([approvalId,p])=>({approvalId,agent:p.agent,tool:p.tool,expires:p.expires,revision:p.revision,args:structuredClone(p.args)}));}
  #evaluate(agent,tool,args,approved=false,consume=false){
    const deny=(reason,rule=null)=>({decision:'deny',reason,rule,risk:'high'});
    if(this.#failed)return deny('Storage unavailable');
    if(!id(agent)||!id(tool)||!plain(args))return deny('Malformed request');
    if(this.#state.halted)return deny('Gateway halted');
    if(this.#state.disabled.includes(agent))return deny('Agent disabled');
    if(Object.values(args).some(v=>typeof v==='string'&&sensitive.test(v)))return deny('Potential credential detected');
    const rules=this.#state.policy.rules.filter(r=>(r.agent===agent||r.agent==='*')&&(r.tool===tool||r.tool==='*'));
    const blocked=rules.find(r=>r.effect==='deny');if(blocked)return deny('Explicit deny',blocked.id);
    if(!this.#tools.has(tool)||!rules.length)return deny('Tool not authorised');
    const invalid=rules.find(r=>!argsMatch(args,r.arguments));if(invalid)return deny('Arguments violate policy',invalid.id);
    const now=this.#clock(),buckets=this.#state.buckets;
    const limited=rules.filter(r=>r.limit).map(r=>{const key=r.id;const old=Object.hasOwn(buckets,key)?buckets[key]:null;return {r,key,b:old&&old.expires>now?old:{count:0,expires:now+r.limit.windowSeconds*1000}};});
    for(const {r,b} of limited)if(b.count>=r.limit.count)return deny('Rate limit exceeded',r.id);
    const review=rules.find(r=>r.effect==='approval');
    if(review&&!approved)return {decision:'approval',reason:'Human review required',rule:review.id,risk:'medium'};
    if(this.#active>=this.#maxConcurrent)return deny('Concurrency limit reached');
    if(consume){
      for(const [k,b] of Object.entries(buckets))if(b.expires<=now)delete buckets[k];
      if(Object.keys(buckets).length+limited.filter(({key})=>!Object.hasOwn(buckets,key)).length>2000)return deny('Quota capacity exceeded');
      for(const {key,b} of limited)Object.defineProperty(buckets,key,{value:{...b,count:b.count+1},enumerable:true,writable:true,configurable:true});
    }
    return {decision:'allow',reason:'Policy permits execution',rule:rules[0].id,risk:'low'};
  }
  preview(agent,tool,args){return this.#evaluate(agent,tool,args);}
  async invoke(agent,tool,args){
    let snap;try{snap=structuredClone(args);}catch{snap=null;}
    return this.#run(agent,tool,snap);
  }
  async #run(agent,tool,args,approved=false){
    this.#expire();
    let d=this.#evaluate(agent,tool,args,approved,true);
    if(d.decision==='approval'&&this.#pending.size>=100)d={decision:'deny',reason:'Approval queue full',rule:d.rule,risk:'high'};
    const safe={agent:id(agent)?agent:'invalid',tool:id(tool)?tool:'invalid'};
    const eventId=this.#log({...safe,...d});
    if(d.decision==='approval'){
      this.#pending.set(eventId,{agent,tool,args,revision:this.#state.revision,expires:this.#clock()+this.#ttl});
      return {...d,eventId,approvalId:eventId};
    }
    if(d.decision!=='allow')return {...d,eventId};
    this.#active++;
    const controller=new AbortController();let timer;
    const start=this.#clock();
    const task=Promise.resolve().then(()=>this.#tools.get(tool)(args,{signal:controller.signal,agent}));
    // Keep capacity reserved until the handler settles, even after the response times out.
    task.then(()=>this.#active--,()=>this.#active--);
    try{
      const result=await Promise.race([task,new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new Error('deadline'));},this.#timeout);})]);
      this.#log({...safe,decision:'executed',reason:'Handler completed',rule:d.rule,requestId:eventId,durationMs:Math.max(0,this.#clock()-start)});
      return {...d,eventId,result};
    }catch{
      const timeout=controller.signal.aborted;
      this.#log({...safe,decision:timeout?'timeout':'error',reason:timeout?'Handler deadline exceeded':'Handler failed',rule:d.rule,requestId:eventId,durationMs:Math.max(0,this.#clock()-start)});
      return {...d,eventId,error:timeout?'Tool deadline exceeded':'Tool execution failed'};
    }finally{clearTimeout(timer);}
  }
  async review(approvalId,approve,reviewer){
    if(!id(reviewer)||typeof approve!=='boolean')throw Error('Invalid review');
    this.#expire();const p=this.#pending.get(approvalId);if(!p)throw Error('Approval unavailable');
    if(reviewer===p.agent)throw Error('Self approval prohibited');
    this.#pending.delete(approvalId);
    this.#log({agent:reviewer,tool:p.tool,decision:approve?'approval_granted':'approval_rejected',reason:approve?'Reviewer authorised request':'Reviewer rejected request',rule:null,requestId:approvalId});
    if(!approve)return {decision:'rejected'};
    if(p.revision!==this.#state.revision)return {decision:'deny',reason:'Policy changed since request'};
    return this.#run(p.agent,p.tool,p.args,true);
  }
  query({decision,agent,tool,limit=100,offset=0}={}){
    if(!Number.isInteger(limit)||limit<1||limit>1000||!Number.isInteger(offset)||offset<0)throw Error('Invalid pagination');
    const items=this.#state.events.filter(e=>(!decision||e.decision===decision)&&(!agent||e.agent===agent)&&(!tool||e.tool===tool)).reverse();
    return {total:items.length,events:structuredClone(items.slice(offset,offset+limit))};
  }
  alerts(){const now=this.#clock();const recent=this.#state.events.filter(e=>now-Date.parse(e.time)<=60000&&e.decision==='deny');const counts=new Map();for(const e of recent)counts.set(e.agent,(counts.get(e.agent)||0)+1);return [...counts].filter(([,count])=>count>=3).map(([agent,count])=>({severity:'high',type:'repeated_denials',agent,count,windowSeconds:60}));}
  metrics(){return Object.entries(this.#state.totals).map(([k,v])=>'agentguard_events_total{decision="'+k+'"} '+v).join('\n')+'\nagentguard_active_handlers '+this.#active+'\n';}
}
