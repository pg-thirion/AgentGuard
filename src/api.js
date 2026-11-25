import {createServer} from 'node:http';
import {AgentGuard} from './guard.js';
import {createAuth} from './auth.js';
const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'"};
async function read(req){
  if(req.headers['content-type']?.split(';')[0]!=='application/json')throw Error('Expected JSON');
  const parts=[];let size=0;
  for await(const c of req){size+=c.length;if(size>32768)throw Error('Request too large');parts.push(c);}
  const data=JSON.parse(Buffer.concat(parts).toString('utf8'));
  if(!data||typeof data!=='object'||Array.isArray(data))throw Error('Expected object');
  return data;
}
export function createApi({gateway,credentials}){
  const authenticate=createAuth(credentials);
  const server=createServer(async(req,res)=>{
    const send=(code,data,type='application/json')=>{res.writeHead(code,{...headers,'Content-Type':type+'; charset=utf-8'});res.end(type==='application/json'?JSON.stringify(data):data);};
    try{
      if(req.headers.origin)return send(403,{error:'Browser cross-origin access disabled'});
      const p=authenticate(req.headers.authorization);
      if(!p)return send(401,{error:'Authentication required'});
      const url=new URL(req.url,'http://localhost'),route=url.pathname,method=req.method;
      const admin=p.role==='admin',reviewer=p.role==='reviewer',observer=admin||reviewer||p.role==='viewer';
      if(method==='GET'&&route==='/health')return send(gateway.status().healthy?200:503,{healthy:gateway.status().healthy});
      if(method==='POST'&&['/v1/invoke','/v1/preview'].includes(route)){
        if(p.role!=='agent')return send(403,{error:'Agent credential required'});
        const b=await read(req);
        if(Object.keys(b).some(k=>!['tool','args'].includes(k)))return send(400,{error:'Unexpected fields'});
        return send(200,route.endsWith('preview')?gateway.preview(p.identity,b.tool,b.args):await gateway.invoke(p.identity,b.tool,b.args));
      }
      if(method==='GET'&&observer){
        if(route==='/v1/status')return send(200,gateway.status());
        if(route==='/v1/policy')return send(200,{policy:gateway.policy,revision:gateway.status().revision});
        if(route==='/v1/history')return send(200,gateway.history());
        if(route==='/v1/alerts')return send(200,gateway.alerts());
        if(route==='/v1/audit/export'){const audit=gateway.audit();return send(200,{...audit,verified:AgentGuard.verifyAudit(audit)});}
        if(route==='/v1/audit')return send(200,gateway.query({decision:url.searchParams.get('decision'),agent:url.searchParams.get('agent'),tool:url.searchParams.get('tool'),limit:Number(url.searchParams.get('limit')??100),offset:Number(url.searchParams.get('offset')??0)}));
        if(route==='/metrics')return send(200,gateway.metrics(),'text/plain');
        if(route==='/v1/approvals'&&reviewer)return send(200,gateway.pending());
      }
      if(method==='POST'&&route==='/v1/review'&&reviewer){const b=await read(req);return send(200,await gateway.review(b.approvalId,b.approve,p.identity));}
      if(method==='POST'&&admin){
        const b=await read(req);
        if(route==='/v1/policy')return send(200,{revision:gateway.setPolicy(b.policy,b.expectedRevision,p.identity)});
        if(route==='/v1/rollback')return send(200,{revision:gateway.rollback(b.revision,b.expectedRevision,p.identity)});
        if(route==='/v1/halt'){gateway.halt(b.halted,p.identity);return send(200,{ok:true});}
        if(route==='/v1/disable'){gateway.disable(b.agent,b.disabled,p.identity);return send(200,{ok:true});}
      }
      return send(403,{error:'Route unavailable for this role'});
    }catch{if(!res.headersSent)send(400,{error:'Request rejected'});}
  });
  server.requestTimeout=10000;server.headersTimeout=5000;server.maxHeadersCount=50;
  return server;
}
