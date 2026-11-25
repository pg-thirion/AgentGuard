import {readFile} from 'node:fs/promises';
import {AgentGuard} from './guard.js';
import {tools,scenarios} from './sandbox.js';
const policy = JSON.parse(await readFile(new URL('../policies/default.json',import.meta.url),'utf8'));
const guard = new AgentGuard({policy,tools});
for (const s of scenarios) console.log(s.label, await guard.invoke(s.agent,s.tool,s.args));
console.log('Audit verified:',AgentGuard.verifyAudit(guard.audit()));
