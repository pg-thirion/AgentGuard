import {createHash,timingSafeEqual} from 'node:crypto';
const digest=v=>createHash('sha256').update(v).digest();
export function createAuth(entries){
  if(!Array.isArray(entries)||!entries.length||entries.length>100)throw Error('Invalid credentials');
  const seen=new Set();
  const records=entries.map(({token,role,identity})=>{
    if(typeof token!=='string'||token.length<32||token.length>256||!['admin','reviewer','viewer','agent'].includes(role)||typeof identity!=='string'||!/^[A-Za-z0-9_-]{1,80}$/.test(identity)||seen.has(token))throw Error('Invalid credential');
    seen.add(token);return {hash:digest(token),role,identity};
  });
  return header=>{
    if(typeof header!=='string'||!header.startsWith('Bearer ')||header.length>263)return null;
    const candidate=digest(header.slice(7));let match=null;
    for(const r of records)if(timingSafeEqual(candidate,r.hash))match={role:r.role,identity:r.identity};
    return match;
  };
}
