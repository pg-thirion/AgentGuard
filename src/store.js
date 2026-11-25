import {createHmac,timingSafeEqual,randomUUID} from 'node:crypto';
import {readFileSync,writeFileSync,renameSync,openSync,fsyncSync,closeSync,unlinkSync} from 'node:fs';
import {dirname} from 'node:path';
const sign=(key,text)=>createHmac('sha256',key).update(text).digest('hex');
export class SignedStore {
  constructor(path,key) {
    if(typeof key!=='string'||Buffer.byteLength(key)<32) throw Error('Storage key must contain at least 32 bytes');
    this.path=path;this.key=key;
  }
  load(fallback) {
    let raw;try{raw=readFileSync(this.path,'utf8');}catch(e){if(e.code==='ENOENT')return structuredClone(fallback);throw e;}
    const {payload,mac}=JSON.parse(raw);
    if(typeof payload!=='string'||typeof mac!=='string'||!/^[a-f0-9]{64}$/.test(mac)||!timingSafeEqual(Buffer.from(mac,'hex'),Buffer.from(sign(this.key,payload),'hex')))throw Error('State integrity check failed');
    return JSON.parse(payload);
  }
  save(state) {
    const payload=JSON.stringify(state),tmp=this.path+'.'+randomUUID()+'.tmp';
    let fd;
    try {
      fd=openSync(tmp,'wx',0o600);writeFileSync(fd,JSON.stringify({payload,mac:sign(this.key,payload)}));fsyncSync(fd);closeSync(fd);fd=undefined;
      renameSync(tmp,this.path);
      const dir=openSync(dirname(this.path),'r');try{fsyncSync(dir);}finally{closeSync(dir);}
    }finally{if(fd!==undefined)closeSync(fd);try{unlinkSync(tmp);}catch(e){if(e.code!=='ENOENT')throw e;}}
  }
}
