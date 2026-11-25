import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {AgentGuard} from './guard.js';
import {Gateway} from './gateway.js';
import {tools,scenarios} from './sandbox.js';
const policy = JSON.parse(await readFile(new URL('../policies/default.json',import.meta.url),'utf8'));
const guard = new Gateway({policy,tools});
const port = Number(process.env.PORT || 8787);
const origin = 'http://127.0.0.1:' + port;
const assets = new Map(await Promise.all([['/','index.html','text/html'],['/app.js','app.js','text/javascript'],['/style.css','style.css','text/css']].map(async ([route,file,type]) => [route,{body:await readFile(new URL('../web/'+file,import.meta.url)),type}])));
const headers = {'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"};
function json(res,status,body) { res.writeHead(status,{...headers,'Content-Type':'application/json; charset=utf-8'}); res.end(JSON.stringify(body)); }
async function body(req) {
  if (req.headers['content-type']?.split(';')[0] !== 'application/json') throw new Error('Expected JSON');
  let size = 0; const parts = [];
  for await (const chunk of req) { size += chunk.length; if (size > 32768) throw new Error('Request too large'); parts.push(chunk); }
  return JSON.parse(Buffer.concat(parts).toString('utf8'));
}
const server = createServer(async (req,res) => {
  if (req.headers.host !== '127.0.0.1:'+port || (req.headers.origin && req.headers.origin !== origin)) return json(res,403,{error:'Local origin only'});
  const route = req.url;
  try {
    if (req.method === 'GET' && assets.has(route)) {
      const asset = assets.get(route); res.writeHead(200,{...headers,'Content-Type':asset.type+'; charset=utf-8'}); return res.end(asset.body);
    }
    if (req.method === 'GET' && route === '/api/state') {
      const audit = guard.audit(); return json(res,200,{policy:guard.policy,scenarios,audit,verified:AgentGuard.verifyAudit(audit),status:guard.status(),approvals:guard.pending(),alerts:guard.alerts(),history:guard.history()});
    }
    if (req.method === 'POST' && route === '/api/invoke') {
      const request = await body(req);
      return json(res,200,await guard.invoke(request.agent,request.tool,request.args));
    }
    if (req.method === 'POST' && route === '/api/policy') { const b=await body(req);guard.setPolicy(b.policy,b.expectedRevision); return json(res,200,{ok:true}); }
    if (req.method === 'POST' && route === '/api/preview') {const b=await body(req);return json(res,200,guard.preview(b.agent,b.tool,b.args));}
    if (req.method === 'POST' && route === '/api/review') {const b=await body(req);return json(res,200,await guard.review(b.approvalId,b.approve,'sandbox-reviewer'));}
    if (req.method === 'POST' && route === '/api/halt') {const b=await body(req);guard.halt(b.halted);return json(res,200,{ok:true});}
    if (req.method === 'POST' && route === '/api/disable') {const b=await body(req);guard.disable(b.agent,b.disabled);return json(res,200,{ok:true});}
    if (req.method === 'POST' && route === '/api/rollback') {const b=await body(req);guard.rollback(b.revision,b.expectedRevision);return json(res,200,{ok:true});}
    return json(res,404,{error:'Not found'});
  } catch { if (!res.headersSent) json(res,400,{error:'Invalid request or policy'}); }
});
server.requestTimeout = 10000;
server.headersTimeout = 5000;
server.listen(port,'127.0.0.1',()=>console.log('AgentGuard sandbox: '+origin));
