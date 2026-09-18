import express from "express";
import path from "path";
import dns from "dns/promises";
import net from "net";
import {fileURLToPath} from "url";

const app=express(),dir=path.dirname(fileURLToPath(import.meta.url));
app.use(express.json({limit:"1mb"})); app.use(express.static(path.join(dir,"public")));

const MAX_DEPTH=5, MAX_BYTES=10_000_000, MAX_CHAIN_BYTES=25_000_000;
// IMPORTANT: recurse only when the fetched text is directly passed to loadstring/load.
// Ordinary HttpGet calls are scanned locally but do not make the executable chain incomplete.
const EXEC_LOADERS=[
 /(?:loadstring|load)\s*\(\s*game\s*:\s*HttpGet(?:Async)?\s*\(\s*["'](https?:\/\/[^"']+)["'][^)]*\)\s*\)\s*\(?/ig,
 /(?:loadstring|load)\s*\(\s*game\.HttpGet(?:Async)?\s*\(\s*game\s*,\s*["'](https?:\/\/[^"']+)["'][^)]*\)\s*\)\s*\(?/ig
];
function executableUrls(s){let out=[];for(const re of EXEC_LOADERS){re.lastIndex=0;let m;while((m=re.exec(s)))out.push(m[1])}return [...new Set(out)]}
function privateIP(ip){if(net.isIP(ip)===4){let a=ip.split(".").map(Number);return a[0]===10||a[0]===127||a[0]===0||(a[0]===169&&a[1]===254)||(a[0]===172&&a[1]>=16&&a[1]<=31)||(a[0]===192&&a[1]===168)}return ip==="::1"||/^(fc|fd|fe80:)/i.test(ip)}
async function checkedURL(raw){let u=new URL(raw);if(!/^https?:$/.test(u.protocol))throw Error("unsupported protocol");let a=await dns.lookup(u.hostname,{all:true});if(!a.length||a.some(x=>privateIP(x.address)))throw Error("private/local destination blocked");return u}
function validate(text,ct=""){let t=text.trim();if(!t)return{ok:false,reason:"empty response"};if(/^<!doctype html|^<html[\s>]/i.test(t)||/text\/html/i.test(ct))return{ok:false,reason:"HTML returned instead of executable Lua"};if(/application\/json/i.test(ct)||/^[\[{]/.test(t)){try{let j=JSON.parse(t);if(j&&typeof j==="object")return{ok:false,reason:j.success===false?`remote API error: ${j.message||j.error||"request failed"}`:"JSON returned instead of executable Lua"}}catch{}}return{ok:true}}
async function fetchText(raw){let u=await checkedURL(raw);for(let i=0;i<5;i++){let r=await fetch(u,{redirect:"manual",headers:{"User-Agent":"LuaGuard/5.0","Accept":"text/plain,text/*,*/*;q=.5"}});if(r.status>=300&&r.status<400&&r.headers.get("location")){u=await checkedURL(new URL(r.headers.get("location"),u).href);continue}if(!r.ok)throw Error("HTTP "+r.status);let len=Number(r.headers.get("content-length")||0);if(len>MAX_BYTES)throw Error(`executable remote source exceeds ${MAX_BYTES} byte inspection limit`);let t=await r.text();if(t.length>MAX_BYTES)throw Error(`executable remote source exceeds ${MAX_BYTES} byte inspection limit`);let v=validate(t,r.headers.get("content-type")||"");if(!v.ok)throw Error(v.reason);return{text:t,url:u.href}}throw Error("too many redirects")}
function line(s,i){return s.slice(0,i).split("\n").length}
function scan(s,source){let f=[];function add(name,severity,why,re){re.lastIndex=0;let m;while((m=re.exec(s)))f.push({name,severity,explanation:why,source,line:line(s,m.index),evidence:m[0].slice(0,120)})}
add("Discord webhook",2,"Webhook found. Review the data being sent.",/https?:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/[^\s"'\\)]+/ig);
add("Outbound request API",1,"Can send data externally. Common in some scripts; not malicious alone.",/\b(?:request|http_request|syn\.request|fluxus\.request|http\.request|HttpPost|PostAsync)\b/ig);
add("Roblox session/cookie targeting",5,"References Roblox session-cookie material.",/(?:\.ROBLOSECURITY|ROBLOSECURITY|roblox.{0,20}cookie|cookie.{0,20}roblox)/ig);
add("Credential/token targeting",4,"References credential/authentication material.",/\b(?:authorization|credentials?|password|auth[_ -]?tokens?|access[_ -]?tokens?|session[_ -]?tokens?)\b/ig);
add("Sensitive local file read",3,"Reads/enumerates local files; higher risk with outbound requests.",/\b(?:readfile|listfiles|isfile)\s*\(/ig);
add("Clipboard access",1,"Touches clipboard data; not malicious alone.",/\b(?:getclipboard|setclipboard|toclipboard)\s*\(/ig);
add("Obfuscation / encoded strings",1,"Encoding/string reconstruction can conceal behavior.",/(?:string\.char\s*\(|\\x[0-9a-f]{2}|bit32\.(?:bxor|bnot)|base64|frombase64)/ig);
let n=new Set(f.map(x=>x.name));
if((n.has("Roblox session/cookie targeting")||n.has("Credential/token targeting"))&&(n.has("Outbound request API")||n.has("Discord webhook")))f.push({name:"Possible credential exfiltration chain",severity:5,explanation:"Account-related material and outbound transmission behavior occur together.",source,line:null,evidence:"behavior combination"});
if(n.has("Sensitive local file read")&&(n.has("Outbound request API")||n.has("Discord webhook")))f.push({name:"Possible local-data exfiltration chain",severity:4,explanation:"Local file access and outbound transmission occur together.",source,line:null,evidence:"behavior combination"});
return f}
async function analyze(code){let findings=scan(code,"Submitted script"),remote=[],seen=new Set(),chainBytes=0;
async function walk(src,depth){let next=executableUrls(src);if(depth>=MAX_DEPTH){if(next.length)remote.push({status:"unverified",url:"Nested executable chain",error:"maximum executable inspection depth reached"});return}
for(let raw of next){if(seen.has(raw))continue;seen.add(raw);try{let g=await fetchText(raw);
chainBytes += g.text.length;
if(chainBytes > MAX_CHAIN_BYTES) throw Error("total executable chain exceeds 25 MB inspection limit");
let cf=scan(g.text,g.url);findings.push(...cf);remote.push({url:g.url,status:"inspected",bytes:g.text.length,findings:cf.length});await walk(g.text,depth+1)}catch(e){remote.push({url:raw,status:"unverified",error:e.message})}}}
await walk(code,0);
let m=findings.filter(x=>x.severity>0),unverified=remote.some(x=>x.status==="unverified"),score=m.reduce((a,x)=>a+x.severity,0);
let strong=m.some(x=>x.name==="Roblox session/cookie targeting"||x.name.includes("exfiltration chain"));
let status=strong||score>=10?"red":m.length||unverified?"yellow":"green";
let summary=status==="red"?"High-risk account-security or data-exfiltration indicators were detected.":status==="yellow"?(unverified?"An executable remote source could not be fully verified. Do not treat the script as confirmed safe.":"Suspicious behavior needs review; no strong account-theft chain was confirmed."):"No account-stealing or exfiltration indicators were detected in the executable code chain LuaGuard inspected.";
return{status,score,summary,findings,remote,complete:!unverified}}
app.post("/api/analyze",async(req,res)=>{let code=typeof req.body?.code==="string"?req.body.code:"";if(!code.trim())return res.status(400).json({error:"Paste a Lua script first."});try{res.json(await analyze(code))}catch(e){res.status(500).json({error:"Analysis failed safely: "+e.message})}});
app.listen(process.env.PORT||3000,()=>console.log("LuaGuard v5 listening"));