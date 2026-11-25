import test from 'node:test';
import assert from 'node:assert/strict';
import {AgentGuard,validatePolicy} from '../src/guard.js';
const allow = {id:'read',agent:'a',tool:'read',effect:'allow',arguments:{id:{type:'string',maxLength:10}},limit:{count:2,windowSeconds:10}};
const deny = {id:'block',agent:'*',tool:'read',effect:'deny'};
function fixture(rules=[allow]) {
  let calls=0, now=0;
  const guard=new AgentGuard({policy:{version:'1',rules},tools:{read:async args=>{calls++;return args.id;}},clock:()=>now});
  return {guard,calls:()=>calls,advance:ms=>{now+=ms;}};
}
test('allow, deny by default, unregistered tool, actual handler execution',async()=>{
  const {guard,calls}=fixture();
  assert.equal((await guard.invoke('a','read',{id:'42'})).result,'42');
  assert.equal((await guard.invoke('b','read',{id:'42'})).decision,'deny');
  assert.equal((await guard.invoke('a','unknown',{})).decision,'deny');
  assert.equal(calls(),1);
});
test('explicit deny wins regardless of rule order',async()=>{
  for(const rules of [[allow,deny],[deny,allow]]) {
    const {guard,calls}=fixture(rules);
    assert.equal((await guard.invoke('a','read',{id:'42'})).decision,'deny');
    assert.equal(calls(),0);
  }
});
test('approval does not invoke the handler',async()=>{
  const {guard,calls}=fixture([allow,{...allow,id:'review',effect:'approval'}]);
  assert.equal((await guard.invoke('a','read',{id:'42'})).decision,'approval');
  assert.equal(calls(),0);
});
test('malformed, extra, missing and oversized arguments fail closed',async()=>{
  const {guard,calls}=fixture();
  for(const args of [null,[],{}, {id:123},{id:'12345678901'},{id:'42',extra:true}]) assert.equal((await guard.invoke('a','read',args)).decision,'deny');
  assert.equal(calls(),0);
});
test('quota, reload resistance and window expiry',async()=>{
  const {guard,advance,calls}=fixture();
  await Promise.all([guard.invoke('a','read',{id:'1'}),guard.invoke('a','read',{id:'2'})]);
  guard.setPolicy({version:'2',rules:[allow]});
  assert.equal((await guard.invoke('a','read',{id:'3'})).decision,'deny');
  advance(10000);
  assert.equal((await guard.invoke('a','read',{id:'4'})).decision,'allow');
  assert.equal(calls(),3);
});
test('audit does not contain raw arguments; modification detected',async()=>{
  const {guard}=fixture();
  await guard.invoke('a','read',{id:'secret'});
  const audit=guard.audit();
  assert.equal(AgentGuard.verifyAudit(audit),true);
  assert.equal(JSON.stringify(audit).includes('secret'),false);
  audit.events[0].reason='changed';
  assert.equal(AgentGuard.verifyAudit(audit),false);
});
test('invalid policy rejected without replacing current policy',async()=>{
  const {guard}=fixture();
  assert.throws(()=>guard.setPolicy({version:'2',rules:[{...allow,effect:'typo'}]}));
  assert.equal(guard.policy.version,'1');
  assert.throws(()=>validatePolicy({version:'1',rules:[allow,allow]}));
});
test('handler failure recorded without leaking error',async()=>{
  const guard=new AgentGuard({policy:{version:'1',rules:[allow]},tools:{read:()=>{throw Error('private');}}});
  const r=await guard.invoke('a','read',{id:'42'});
  assert.equal(r.error,'Tool execution failed');
  assert.equal(guard.audit().events.at(-1).decision,'error');
  assert.equal(JSON.stringify(guard.audit()).includes('private'),false);
});
test('wildcard identities share rule quota',async()=>{
  const {guard}=fixture([{...allow,agent:'*'}]);
  await guard.invoke('a','read',{id:'1'});
  await guard.invoke('b','read',{id:'2'});
  assert.equal((await guard.invoke('c','read',{id:'3'})).decision,'deny');
});
