import { createHash, randomUUID } from 'node:crypto';

const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const identifier = v => typeof v === 'string' && /^[a-zA-Z0-9_-]{1,80}$/.test(v);
const hash = v => createHash('sha256').update(JSON.stringify(v)).digest('hex');
const effects = new Set(['allow', 'deny', 'approval']);
const own = (o,k) => Object.hasOwn(o,k);
const fail = msg => { throw new TypeError(msg); };
const only = (o, keys) => Object.keys(o).every(k => keys.includes(k));

export function validatePolicy(p) {
  if (!plain(p) || !only(p,['version','rules']) || !identifier(p.version) || !Array.isArray(p.rules) || p.rules.length > 200) fail('Invalid policy');
  const ids = new Set();
  for (const r of p.rules) {
    if (!plain(r) || !only(r,['id','agent','tool','effect','arguments','limit']) || !identifier(r.id) || ids.has(r.id) || !(r.agent === '*' || identifier(r.agent)) || !(r.tool === '*' || identifier(r.tool)) || !effects.has(r.effect)) fail('Invalid or duplicate rule');
    ids.add(r.id);
    if (r.effect !== 'deny' && (!plain(r.arguments) || Object.keys(r.arguments).length > 30 || r.tool === '*')) fail('Allow and approval rules require an exact tool and argument schema');
    if (r.arguments !== undefined) {
      if (!plain(r.arguments)) fail('Invalid arguments schema');
      for (const [key,s] of Object.entries(r.arguments)) {
        if (!identifier(key) || ['__proto__','constructor','prototype'].includes(key) || !plain(s) || !only(s,['type','maxLength','values']) || !['string','number','boolean'].includes(s.type)) fail('Invalid argument schema');
        if (s.type === 'string' && (!Number.isInteger(s.maxLength ?? 256) || (s.maxLength ?? 256) < 1 || (s.maxLength ?? 256) > 4096)) fail('Invalid maximum length');
        if (s.maxLength !== undefined && s.type !== 'string') fail('Length only applies to strings');
        if (s.values !== undefined && (!Array.isArray(s.values) || s.values.length === 0 || s.values.length > 100 || !s.values.every(v => typeof v === s.type && (s.type !== 'number' || Number.isFinite(v))))) fail('Invalid allowed values');
      }
    }
    if (r.limit !== undefined && (!plain(r.limit) || !only(r.limit,['count','windowSeconds']) || !Number.isInteger(r.limit.count) || r.limit.count < 1 || r.limit.count > 10000 || !Number.isInteger(r.limit.windowSeconds) || r.limit.windowSeconds < 1 || r.limit.windowSeconds > 3600)) fail('Invalid rate limit');
  }
  return structuredClone(p);
}

function validArgs(args, schema) {
  if (!plain(args) || Object.keys(args).length !== Object.keys(schema).length) return false;
  return Object.entries(schema).every(([k,s]) => {
    if (!own(args,k)) return false;
    const v = args[k];
    return typeof v === s.type && (s.type !== 'string' || v.length <= (s.maxLength ?? 256)) && (s.type !== 'number' || Number.isFinite(v)) && (!s.values || s.values.includes(v));
  });
}

export class AgentGuard {
  #policy; #registry; #buckets = new Map(); #events = []; #clock; #anchor = '0'.repeat(64);
  constructor({policy, tools = {}, clock = Date.now} = {}) {
    this.#policy = validatePolicy(policy);
    this.#registry = new Map(Object.entries(tools));
    this.#clock = clock;
    if ([...this.#registry].some(([name,fn]) => !identifier(name) || typeof fn !== 'function')) fail('Invalid tool registry');
  }
  get policy() { return structuredClone(this.#policy); }
  setPolicy(policy) {
    const next = validatePolicy(policy);
    this.#policy = next;
    // Keep existing buckets: reloading a policy must not reset its quotas.
    this.#record({agent:'operator',tool:'policy_update',decision:'policy_updated',reason:'Policy replaced',rule:null});
  }
  #record(fields) {
    const event = { id:randomUUID(), time:new Date(this.#clock()).toISOString(), policyVersion:this.#policy.version, ...fields, previousHash:this.#events.at(-1)?.hash ?? this.#anchor };
    event.hash = hash(event);
    this.#events.push(event);
    if (this.#events.length > 1000) this.#anchor = this.#events.shift().hash;
    return structuredClone(event);
  }
  audit() { return {anchor:this.#anchor, events:structuredClone(this.#events)}; }
  static verifyAudit({anchor,events}) {
    if (typeof anchor !== 'string' || !Array.isArray(events)) return false;
    let prev = anchor;
    for (const event of events) {
      const {hash: digest,...rest} = event;
      if (rest.previousHash !== prev || hash(rest) !== digest) return false;
      prev = digest;
    }
    return true;
  }
  #decide(agent,tool,args) {
    if (!identifier(agent) || !identifier(tool) || !plain(args)) return ['deny','Malformed request',null];
    const matches = this.#policy.rules.filter(r => (r.agent === agent || r.agent === '*') && (r.tool === tool || r.tool === '*'));
    const denied = matches.find(r => r.effect === 'deny');
    if (denied) return ['deny','Explicit deny',denied.id];
    if (!this.#registry.has(tool)) return ['deny','Unregistered tool',null];
    if (!matches.length) return ['deny','No matching rule',null];
    // All overlapping non-deny rules must permit these arguments. Approval takes precedence.
    const invalid = matches.find(r => !validArgs(args,r.arguments));
    if (invalid) return ['deny','Arguments violate policy',invalid.id];
    const approval = matches.find(r => r.effect === 'approval');
    if (approval) return ['approval','Human review required; no execution',approval.id];
    const now = this.#clock();
    for (const [key,b] of this.#buckets) if (b.expires <= now) this.#buckets.delete(key);
    const checks = matches.filter(r => r.limit).map(r => {
      // Shared per-rule quota prevents bypass by inventing agent IDs under wildcard rules.
      const key = r.id + ':' + r.tool;
      const b = this.#buckets.get(key) ?? {count:0,expires:now + r.limit.windowSeconds*1000};
      return {r,key,b};
    });
    for (const {r,key,b} of checks) {
      if (b.count >= r.limit.count) return ['deny','Rate limit exceeded',r.id];
      if (!this.#buckets.has(key) && this.#buckets.size >= 2000) return ['deny','Quota storage exhausted',r.id];
    }
    for (const {key,b} of checks) this.#buckets.set(key,{...b,count:b.count+1});
    return ['allow','Policy permits execution',matches[0].id];
  }
  // agent must come from the trusted host identity, never from model-generated arguments.
  async invoke(agent,tool,args) {
    let snapshot;
    try { snapshot = structuredClone(args); } catch { snapshot = null; }
    const [decision,reason,rule] = this.#decide(agent,tool,snapshot);
    const safeAgent = identifier(agent) ? agent : 'invalid';
    const safeTool = identifier(tool) ? tool : 'invalid';
    const event = this.#record({agent:safeAgent,tool:safeTool,decision,reason,rule});
    if (decision !== 'allow') return {decision,reason,rule,eventId:event.id};
    try {
      const result = await this.#registry.get(tool)(snapshot);
      this.#record({agent:safeAgent,tool:safeTool,decision:'executed',reason:'Handler completed',rule,requestId:event.id});
      return {decision,reason,rule,eventId:event.id,result};
    } catch {
      this.#record({agent:safeAgent,tool:safeTool,decision:'error',reason:'Handler failed',rule,requestId:event.id});
      return {decision,reason,rule,eventId:event.id,error:'Tool execution failed'};
    }
  }
}
