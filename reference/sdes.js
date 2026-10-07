// 独立位数组实现：不导入 Python 或其算法代码。
const fs = require('fs');
const crypto = require('crypto');
const select = (bits, positions) => positions.map(p => bits[p-1]);
const rotate = (bits,n) => bits.slice(n).concat(bits.slice(0,n));
const xor = (a,b) => a.map((v,i)=>v^b[i]);
const bits = (n,w) => n.toString(2).padStart(w,'0').split('').map(Number);
const number = a => parseInt(a.join(''),2);
const boxA = [[1,0,3,2],[3,2,1,0],[0,2,1,3],[3,1,0,2]];
const boxB = [[0,1,2,3],[2,3,1,0],[3,0,1,2],[2,1,0,3]];
function keys(n) {
  const state = select(bits(n,10),[3,5,2,7,4,10,1,9,8,6]);
  const a=state.slice(0,5), b=state.slice(5);
  return [1,2].map(shift=>select(rotate(a,shift).concat(rotate(b,shift)),[6,3,7,4,8,5,10,9]));
}
function substitution(a,table) { return bits(table[a[0]*2+a[3]][a[1]*2+a[2]],2); }
function round(a,k) {
  const r=a.slice(4), mixed=xor(select(r,[4,1,2,3,2,3,4,1]),k);
  const s=substitution(mixed.slice(0,4),boxA).concat(substitution(mixed.slice(4),boxB));
  return xor(a.slice(0,4),select(s,[2,4,3,1])).concat(r);
}
function crypt(n,ks,decrypt=false) {
  const order=decrypt?[ks[1],ks[0]]:ks;
  let a=round(select(bits(n,8),[2,6,3,1,4,8,5,7]),order[0]);
  a=round(a.slice(4).concat(a.slice(0,4)),order[1]);
  return number(select(a,[4,1,3,5,7,2,8,6]));
}
if (require.main===module) {
  const [input,output]=process.argv.slice(2);
  if (input==='--summary') {
    const hash=crypto.createHash('sha256');
    let roundtripErrors=0;
    const samples=[];
    for (let key=0;key<1024;key++) {
      const ks=keys(key);
      for (let plain=0;plain<256;plain++) {
        const cipher=crypt(plain,ks);
        hash.update(Buffer.from([cipher]));
        if (crypt(cipher,ks,true)!==plain) roundtripErrors++;
        if (samples.length<8 && (key*256+plain)%32767===0) samples.push({key,plain,cipher});
      }
    }
    console.log(JSON.stringify({records:262144,sha256:hash.digest('hex'),roundtripErrors,samples,node:process.version}));
    process.exit(0);
  }
  if (!input || !output) throw Error('用法: node reference/sdes.js 输入.json 输出.json');
  const records=JSON.parse(fs.readFileSync(input,'utf8'));
  const cache=Array.from({length:1024},(_,k)=>keys(k));
  const results=records.map(r=>({key:r.key,plain:r.plain,cipher:crypt(r.plain,cache[r.key]),
    decrypted:crypt(r.cipher,cache[r.key],true)}));
  fs.writeFileSync(output,JSON.stringify(results));
  console.log(JSON.stringify({records:results.length,node:process.version}));
}
module.exports={keys,crypt};
