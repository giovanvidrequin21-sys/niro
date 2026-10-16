#!/usr/bin/env node
/* =====================================================================
   ATELIER : serveur d'authentification et de protection du site
   Aucune dépendance externe : uniquement les modules intégrés de Node (22 ou plus).

   Ce que ce serveur garantit (et que les tests de ./tests vérifient) :
   - le site n'est envoyé QU'à une session valide : sans connexion, aucune ligne du site n'est transmise ;
   - mots de passe hachés avec scrypt (sel aléatoire par compte), jamais stockés ni journalisés en clair ;
   - sessions : jeton aléatoire de 256 bits, seul son hash est stocké côté serveur ; cookie HttpOnly,
     SameSite=Strict (et Secure en HTTPS) ; expiration d'inactivité et expiration absolue ; révocation côté serveur ;
   - limitation des tentatives par adresse IP et par compte, verrouillage progressif ;
   - requêtes qui modifient l'état : JSON uniquement, en-tête personnalisé, contrôle de l'origine (anti-CSRF) ;
   - en-têtes de sécurité, dont une politique CSP à jeton unique par réponse ;
   - aucune URL n'est convertie en chemin de fichier : pas de traversée de répertoire possible.

   Ce qu'il NE fait PAS (voir README) : e-mail de vérification ou de réinitialisation, double authentification,
   protection contre les attaques distribuées, chiffrement du disque. HTTPS est indispensable en production.
   ===================================================================== */
'use strict';
const http=require('node:http'),https=require('node:https'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),readline=require('node:readline');

/* ---------- configuration (variables d'environnement) ---------- */
const env=process.env,int=(k,d)=>{const n=parseInt(env[k],10);return Number.isFinite(n)&&n>0?n:d;};
const CFG={
  port:int('PORT',3000),host:env.HOST||'0.0.0.0'
  dataDir:path.resolve(env.DATA_DIR||path.join(__dirname,'data')),
  siteDir:path.resolve(env.SITE_DIR||path.join(__dirname,'site')),
  registration:['open','invite','closed'].includes(env.REGISTRATION)?env.REGISTRATION:'invite',
  cookieSecure:env.COOKIE_SECURE||'auto',trustProxy:env.TRUST_PROXY==='1',
  idle:int('SESSION_IDLE_SECONDS',12*3600)*1000,absolute:int('SESSION_MAX_SECONDS',7*24*3600)*1000,
  maxSessions:int('MAX_SESSIONS_PER_USER',10),
  scryptN:int('SCRYPT_N',32768),scryptR:8,scryptP:1,
  tlsCert:env.TLS_CERT,tlsKey:env.TLS_KEY,
  ipLimit:int('IP_AUTH_LIMIT',30),ipAnyLimit:int('IP_ANY_LIMIT',120),ipWindow:int('IP_AUTH_WINDOW_SECONDS',600)*1000,regPerHour:int('REG_PER_IP_PER_HOUR',10),
  lockAfter:int('LOCK_AFTER_FAILURES',5)
};
const log=(event,o={})=>{if(env.QUIET==='1')return;process.stdout.write(JSON.stringify({t:new Date().toISOString(),event,...o})+'\n');};

/* ---------- stockage : fichiers JSON écrits de façon atomique, droits restreints ---------- */
fs.mkdirSync(CFG.dataDir,{recursive:true,mode:0o700});
const files={users:path.join(CFG.dataDir,'users.json'),sessions:path.join(CFG.dataDir,'sessions.json'),invites:path.join(CFG.dataDir,'invites.json')};
const load=(f,d)=>{try{return JSON.parse(fs.readFileSync(f,'utf8'));}catch(_){return d;}};
const DB={users:load(files.users,{next:1,byName:{}}),sessions:load(files.sessions,{}),invites:load(files.invites,{})};
const timers={},mt={},dirty=new Set();let CLI=false;
const statM=f=>{try{return fs.statSync(f).mtimeMs;}catch(_){return 0;}};
Object.keys(files).forEach(k=>{mt[k]=statM(files[k]);});
/* La ligne de commande (create-user, revoke-sessions…) écrit dans les mêmes fichiers pendant que le serveur tourne :
   le serveur recharge tout fichier modifié de l'extérieur, et n'écrase jamais un changement qu'il n'a pas vu. */
function reloadIfChanged(k){const m=statM(files[k]);if(m!==mt[k]){DB[k]=load(files[k],DB[k]);mt[k]=m;return true;}return false;}
let lastRefresh=0;function refresh(){const n=Date.now();if(n-lastRefresh<500)return;lastRefresh=n;Object.keys(files).forEach(reloadIfChanged);}
function writeNow(k){if(!CLI&&reloadIfChanged(k)){dirty.delete(k);return;}const tmp=files[k]+'.'+process.pid+'.tmp';fs.writeFileSync(tmp,JSON.stringify(DB[k]),{mode:0o600});fs.renameSync(tmp,files[k]);mt[k]=statM(files[k]);dirty.delete(k);}
function save(k){dirty.add(k);clearTimeout(timers[k]);if(k!=='sessions'){try{writeNow(k);}catch(e){log('save_error',{k,msg:e.message});}return;}timers[k]=setTimeout(()=>{try{writeNow(k);}catch(e){log('save_error',{k,msg:e.message});}},150);}
/* n'écrit que les fichiers réellement modifiés : une commande ne doit jamais réécrire (et donc écraser) les autres */
function flushAll(){[...dirty].forEach(k=>{clearTimeout(timers[k]);try{writeNow(k);}catch(_){}});}

/* ---------- mots de passe ---------- */
const scrypt=(pw,salt,N,r,p,len)=>new Promise((res,rej)=>crypto.scrypt(pw,salt,len,{N,r,p,maxmem:256*N*r},(e,k)=>e?rej(e):res(k)));
let hashing=0;   // limite de calculs simultanés : évite qu'un afflux de requêtes sature la mémoire
async function guarded(fn){if(hashing>=8){const e=new Error('busy');e.busy=true;throw e;}hashing++;try{return await fn();}finally{hashing--;}}
const norm=s=>String(s).normalize('NFKC');
async function hashPassword(pw){const salt=crypto.randomBytes(16);const key=await scrypt(norm(pw),salt,CFG.scryptN,CFG.scryptR,CFG.scryptP,64);return ['scrypt',CFG.scryptN,CFG.scryptR,CFG.scryptP,salt.toString('base64'),key.toString('base64')].join('$');}
async function verifyPassword(pw,stored){
  const p=String(stored).split('$');if(p[0]!=='scrypt'||p.length!==6)return false;
  const N=+p[1],r=+p[2],pp=+p[3],salt=Buffer.from(p[4],'base64'),want=Buffer.from(p[5],'base64');
  if(!(N>=16384&&N<=1048576&&r>=1&&pp>=1))return false;
  const got=await scrypt(norm(pw),salt,N,r,pp,want.length);
  return got.length===want.length&&crypto.timingSafeEqual(got,want);
}
let DUMMY=null;   // compte factice : un nom inconnu coûte le même temps de calcul qu'un mot de passe faux
const COMMON=new Set(['password','password1','password123','123456789','1234567890','12345678910','azertyuiop','azerty123456','motdepasse','motdepasse1','qwertyuiop','qwerty123456','iloveyou123','admin12345','administrator','letmein1234','welcome1234','000000000000','111111111111','changeme123','abcdefghij','1q2w3e4r5t','azertyazerty','passw0rd123']);
function passwordProblem(pw,username){
  if(typeof pw!=='string')return 'Mot de passe invalide.';
  const n=[...norm(pw)].length;
  if(n<10)return 'Le mot de passe doit contenir au moins 10 caractères.';
  if(n>128)return 'Le mot de passe est trop long (128 caractères maximum).';
  const low=norm(pw).toLowerCase();
  if(COMMON.has(low))return 'Ce mot de passe est trop courant. Choisissez-en un autre.';
  if(new Set([...low]).size<4)return 'Ce mot de passe est trop répétitif.';
  if(username&&username.length>=4&&low.includes(username.toLowerCase()))return 'Le mot de passe ne doit pas contenir votre nom d\'utilisateur.';
  return null;
}
const USER_RE=/^[a-z0-9][a-z0-9_.-]{2,31}$/;

/* ---------- limitation des tentatives ---------- */
const ipAny=new Map(),ipFail=new Map(),ipReg=new Map(),fails=new Map();
const recent=(map,ip,win)=>{const now=Date.now(),a=(map.get(ip)||[]).filter(t=>now-t<win);map.set(ip,a);return a;};
/* Trois compteurs par adresse IP : 1) toutes les requêtes d'authentification (plafond large contre l'inondation),
   2) les ÉCHECS seulement (un foyer ou un bureau derrière la même adresse ne se bloque pas avec des connexions réussies),
   3) les inscriptions réussies (par heure). Renvoie le nombre de secondes à attendre, ou 0. */
function ipBlocked(ip){
  const now=Date.now(),any=recent(ipAny,ip,CFG.ipWindow);any.push(now);
  if(any.length>CFG.ipAnyLimit)return Math.ceil((any[0]+CFG.ipWindow-now)/1000);
  const f=recent(ipFail,ip,CFG.ipWindow);if(f.length>=CFG.ipLimit)return Math.ceil((f[0]+CFG.ipWindow-now)/1000);
  return 0;
}
const ipFailed=ip=>recent(ipFail,ip,CFG.ipWindow).push(Date.now());
const regBlocked=ip=>{const r=recent(ipReg,ip,3600000);return r.length>=CFG.regPerHour?Math.ceil((r[0]+3600000-Date.now())/1000):0;};
function lockLeft(name){const f=fails.get(name);if(!f||!f.until)return 0;const d=f.until-Date.now();return d>0?Math.ceil(d/1000):0;}
function noteFail(name){const f=fails.get(name)||{n:0,until:0};f.n++;f.last=Date.now();if(f.n>=CFG.lockAfter)f.until=Date.now()+Math.min(15*60*1000*2**(f.n-CFG.lockAfter),24*3600*1000);fails.set(name,f);}
const clearFails=name=>fails.delete(name);
setInterval(()=>{const now=Date.now();for(const m of[ipAny,ipFail]){for(const[k,a]of m){if(!a.some(t=>now-t<CFG.ipWindow))m.delete(k);}}for(const[k,a]of ipReg){if(!a.some(t=>now-t<3600000))ipReg.delete(k);}for(const[k,f]of fails){if(now-f.last>24*3600*1000)fails.delete(k);}for(const[h,s]of Object.entries(DB.sessions)){if(sessionExpired(s,now))delete DB.sessions[h];}save('sessions');},60000).unref();

/* ---------- sessions ---------- */
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const sessionExpired=(s,now)=>now-s.created>CFG.absolute||now-s.last>CFG.idle;
function newSession(uid){
  const token=crypto.randomBytes(32).toString('base64url'),mine=Object.entries(DB.sessions).filter(([,s])=>s.uid===uid).sort((a,b)=>a[1].created-b[1].created);
  while(mine.length>=CFG.maxSessions){delete DB.sessions[mine.shift()[0]];}
  DB.sessions[sha(token)]={uid,created:Date.now(),last:Date.now(),saved:Date.now()};save('sessions');return token;
}
function revokeUser(uid,exceptHash){for(const[h,s]of Object.entries(DB.sessions)){if(s.uid===uid&&h!==exceptHash)delete DB.sessions[h];}save('sessions');}
const userById=id=>Object.values(DB.users.byName).find(u=>u.id===id)||null;

/* ---------- utilitaires HTTP ---------- */
const clientIp=req=>{if(CFG.trustProxy){const x=String(req.headers['x-forwarded-for']||'').split(',').map(s=>s.trim()).filter(Boolean);if(x.length)return x[x.length-1];}return req.socket.remoteAddress||'?';};
const isSecure=req=>CFG.cookieSecure==='1'||(CFG.cookieSecure!=='0'&&(!!req.socket.encrypted||(CFG.trustProxy&&req.headers['x-forwarded-proto']==='https')));
const cookieName=req=>isSecure(req)?'__Host-sid':'sid';
function readCookie(req){const out={};String(req.headers.cookie||'').split(';').forEach(p=>{const i=p.indexOf('=');if(i>0)out[p.slice(0,i).trim()]=p.slice(i+1).trim();});return out['__Host-sid']||out.sid||null;}
function setCookie(res,req,token,maxAgeSec){const a=[`${cookieName(req)}=${token}`,'Path=/','HttpOnly','SameSite=Strict',`Max-Age=${maxAgeSec}`];if(isSecure(req))a.push('Secure');append(res,'Set-Cookie',a.join('; '));}
function append(res,k,v){const p=res.getHeader(k);res.setHeader(k,p?[].concat(p,v):v);}
function baseHeaders(res,req){
  res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Cross-Origin-Opener-Policy','same-origin');res.setHeader('Cross-Origin-Resource-Policy','same-origin');
  res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=(), payment=()');res.setHeader('Cache-Control','no-store');
  if(isSecure(req))res.setHeader('Strict-Transport-Security','max-age=15552000; includeSubDomains');
}
const csp=nonce=>`default-src 'none'; script-src 'nonce-${nonce}'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`;
function sendJson(res,code,obj,extra){res.statusCode=code;res.setHeader('Content-Type','application/json; charset=utf-8');if(extra)for(const k in extra)res.setHeader(k,extra[k]);res.end(JSON.stringify(obj));}
function redirect(res,to){res.statusCode=302;res.setHeader('Location',to);res.end();}
function sendHtml(res,html,nonce){res.statusCode=200;res.setHeader('Content-Type','text/html; charset=utf-8');res.setHeader('Content-Security-Policy',csp(nonce));res.end(html);}
const jsonForScript=o=>JSON.stringify(o).replace(/</g,'\\u003c').replace(/>/g,'\\u003e').replace(/&/g,'\\u0026');
function readBody(req){return new Promise((res,rej)=>{let n=0;const c=[];req.on('data',d=>{n+=d.length;if(n>4096){rej(Object.assign(new Error('big'),{code:413}));req.destroy();}else c.push(d);});req.on('end',()=>{try{res(JSON.parse(Buffer.concat(c).toString('utf8')||'{}'));}catch(_){rej(Object.assign(new Error('json'),{code:400}));}});req.on('error',rej);});}
function sameOrigin(req){
  const host=String((CFG.trustProxy&&req.headers['x-forwarded-host'])||req.headers.host||'');
  const o=req.headers.origin;
  if(o){try{return new URL(o).host===host;}catch(_){return false;}}
  const sf=req.headers['sec-fetch-site'];
  return !sf||sf==='same-origin'||sf==='none';
}
function stateChangeAllowed(req){
  return /^application\/json\b/i.test(String(req.headers['content-type']||''))&&!!req.headers['x-requested-with']&&sameOrigin(req);
}
function currentSession(req){
  const t=readCookie(req);if(!t||t.length>100)return null;
  const h=sha(t),s=DB.sessions[h];if(!s)return null;
  const now=Date.now();if(sessionExpired(s,now)){delete DB.sessions[h];save('sessions');return null;}
  const u=userById(s.uid);if(!u){delete DB.sessions[h];save('sessions');return null;}
  s.last=now;if(now-(s.saved||0)>60000){s.saved=now;save('sessions');}
  return {hash:h,user:u};
}

/* ---------- pages ---------- */
const readSite=f=>fs.readFileSync(path.join(CFG.siteDir,f),'utf8');
let SITE=null,LOGIN=null;
function loadPages(){SITE=readSite('index.html');LOGIN=readSite('login.html');}
function renderSite(user){
  const nonce=crypto.randomBytes(16).toString('base64');
  const sess=`<script nonce="${nonce}">window.__SESSION__=${jsonForScript({uid:user.id,name:user.name})};</script>`;
  let html=SITE.replace('<!--SESSION-->',()=>sess).replace('<script>',()=>`<script nonce="${nonce}">`);
  return {html,nonce};
}
function renderLogin(){const nonce=crypto.randomBytes(16).toString('base64');return {html:LOGIN.replace(/\{\{NONCE\}\}/g,nonce).replace('{{CFG}}',()=>jsonForScript({registration:CFG.registration})),nonce};}

/* ---------- routes ---------- */
const GENERIC='Identifiant ou mot de passe incorrect.';
async function login(req,res){
  const ip=clientIp(req),wait=ipBlocked(ip);
  if(wait)return sendJson(res,429,{error:`Trop de tentatives. Réessayez dans ${Math.ceil(wait/60)} minute(s).`},{'Retry-After':String(wait)});
  const b=await readBody(req),name=String(b.username||'').trim().toLowerCase().slice(0,64),pw=typeof b.password==='string'?b.password.slice(0,256):'';
  if(!name||!pw)return sendJson(res,400,{error:'Renseignez votre nom d\'utilisateur et votre mot de passe.'});
  const lock=lockLeft(name);if(lock)return sendJson(res,429,{error:`Trop de tentatives. Réessayez dans ${Math.ceil(lock/60)} minute(s).`},{'Retry-After':String(lock)});
  const u=DB.users.byName[name];
  const ok=await guarded(()=>verifyPassword(pw,u?u.hash:DUMMY));
  if(!u||!ok){noteFail(name);ipFailed(ip);log('login_fail',{ip,user:name.slice(0,32)});return sendJson(res,401,{error:GENERIC});}
  clearFails(name);
  const old=readCookie(req);if(old)delete DB.sessions[sha(old)];   // pas de réutilisation d'une session existante (fixation)
  setCookie(res,req,newSession(u.id),Math.floor(CFG.absolute/1000));log('login_ok',{ip,user:name});
  sendJson(res,200,{ok:true});
}
async function register(req,res){
  const ip=clientIp(req);
  if(CFG.registration==='closed')return sendJson(res,403,{error:'Les inscriptions sont fermées.'});
  const wait=ipBlocked(ip)||regBlocked(ip);if(wait)return sendJson(res,429,{error:`Trop de tentatives. Réessayez dans ${Math.ceil(wait/60)} minute(s).`},{'Retry-After':String(wait)});
  const b=await readBody(req),name=String(b.username||'').trim().toLowerCase(),pw=b.password;
  if(!USER_RE.test(name))return sendJson(res,400,{error:'Nom d\'utilisateur : 3 à 32 caractères (lettres minuscules, chiffres, point, tiret, tiret bas), en commençant par une lettre ou un chiffre.'});
  const prob=passwordProblem(pw,name);if(prob)return sendJson(res,400,{error:prob});
  let inviteHash=null;
  if(CFG.registration==='invite'){
    const code=String(b.invite||'').trim().toUpperCase().slice(0,64);inviteHash=sha(code);const inv=code&&DB.invites[inviteHash];
    if(!inv||inv.uses>=inv.maxUses||(inv.expires&&Date.now()>inv.expires)){noteFail('invite:'+ip);ipFailed(ip);log('register_bad_invite',{ip});return sendJson(res,403,{error:'Code d\'invitation invalide ou expiré.'});}
  }
  if(DB.users.byName[name])return sendJson(res,409,{error:'Ce nom d\'utilisateur est déjà pris.'});
  const hash=await guarded(()=>hashPassword(pw));
  if(DB.users.byName[name])return sendJson(res,409,{error:'Ce nom d\'utilisateur est déjà pris.'});   // course entre deux inscriptions simultanées
  const u={id:DB.users.next++,name,hash,created:Date.now(),admin:false};DB.users.byName[name]=u;save('users');
  if(inviteHash){DB.invites[inviteHash].uses++;save('invites');}
  recent(ipReg,ip,3600000).push(Date.now());
  const old=readCookie(req);if(old)delete DB.sessions[sha(old)];
  setCookie(res,req,newSession(u.id),Math.floor(CFG.absolute/1000));log('register',{ip,user:name});
  sendJson(res,201,{ok:true});
}
async function changePassword(req,res,sess){
  const b=await readBody(req),cur=typeof b.current==='string'?b.current.slice(0,256):'',nw=b.new;
  const lock=lockLeft(sess.user.name);if(lock)return sendJson(res,429,{error:'Trop de tentatives.'},{'Retry-After':String(lock)});
  if(!(await guarded(()=>verifyPassword(cur,sess.user.hash)))){noteFail(sess.user.name);return sendJson(res,403,{error:'Mot de passe actuel incorrect.'});}
  const prob=passwordProblem(nw,sess.user.name);if(prob)return sendJson(res,400,{error:prob});
  sess.user.hash=await guarded(()=>hashPassword(nw));save('users');clearFails(sess.user.name);
  revokeUser(sess.user.id);   // toutes les autres sessions sont fermées
  setCookie(res,req,newSession(sess.user.id),Math.floor(CFG.absolute/1000));log('password_changed',{user:sess.user.name});
  sendJson(res,200,{ok:true});
}
async function handle(req,res){
  refresh();
  baseHeaders(res,req);
  let url;try{url=new URL(req.url,'http://local');}catch(_){res.statusCode=400;return res.end();}
  const p=url.pathname,m=req.method;
  if(p==='/healthz'&&m==='GET'){res.setHeader('Content-Type','text/plain');return res.end('ok');}
  if(p==='/login'){
    if(m!=='GET'&&m!=='HEAD'){res.statusCode=405;return res.end();}
    if(currentSession(req))return redirect(res,'/');
    const r=renderLogin();return sendHtml(res,r.html,r.nonce);
  }
  if(p==='/'||p==='/index.html'){
    if(m!=='GET'&&m!=='HEAD'){res.statusCode=405;return res.end();}
    const s=currentSession(req);
    if(!s)return redirect(res,'/login');                 // aucune ligne du site n'est envoyée
    if(p!=='/')return redirect(res,'/');
    const r=renderSite(s.user);return sendHtml(res,r.html,r.nonce);
  }
  if(p.startsWith('/api/')){
    if(p==='/api/me'&&m==='GET'){const s=currentSession(req);return s?sendJson(res,200,{uid:s.user.id,name:s.user.name,admin:!!s.user.admin}):sendJson(res,401,{error:'Non connecté.'});}
    if(m!=='POST'){res.statusCode=405;return res.end();}
    if(!stateChangeAllowed(req))return sendJson(res,403,{error:'Requête refusée.'});
    try{
      if(p==='/api/login')return await login(req,res);
      if(p==='/api/register')return await register(req,res);
      if(p==='/api/logout'){const t=readCookie(req);if(t){delete DB.sessions[sha(t)];save('sessions');}setCookie(res,req,'',0);return sendJson(res,200,{ok:true});}
      if(p==='/api/change-password'){const s=currentSession(req);if(!s)return sendJson(res,401,{error:'Non connecté.'});return await changePassword(req,res,s);}
    }catch(e){
      if(e.busy)return sendJson(res,503,{error:'Serveur occupé, réessayez dans un instant.'},{'Retry-After':'3'});
      if(e.code===413)return sendJson(res,413,{error:'Requête trop volumineuse.'});
      if(e.code===400)return sendJson(res,400,{error:'Requête invalide.'});
      log('error',{msg:e.message});return sendJson(res,500,{error:'Erreur interne.'});
    }
  }
  res.statusCode=404;res.setHeader('Content-Type','text/plain; charset=utf-8');res.end('Introuvable');
}

/* ---------- ligne de commande : comptes et invitations ---------- */
function ask(prompt,secret){
  return new Promise(resolve=>{
    if(!process.stdin.isTTY){let d='';process.stdin.setEncoding('utf8');process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>resolve(d.split(/\r?\n/)[0]));return;}
    process.stdout.write(prompt);let v='';process.stdin.setRawMode(true);process.stdin.resume();process.stdin.setEncoding('utf8');
    const on=ch=>{for(const c of ch){if(c==='\r'||c==='\n'){process.stdin.setRawMode(false);process.stdin.pause();process.stdin.removeListener('data',on);process.stdout.write('\n');return resolve(v);}if(c==='\u0003')process.exit(1);if(c==='\u007f'){v=v.slice(0,-1);}else v+=c;if(!secret)process.stdout.write(c);}};
    process.stdin.on('data',on);
  });
}
async function cli(cmd,args){
  DUMMY=null;CLI=true;
  const flag=f=>args.includes(f),val=f=>{const i=args.indexOf(f);return i>=0?args[i+1]:undefined;};
  if(cmd==='create-user'||cmd==='reset-password'){
    const name=String(args[0]||'').toLowerCase();if(!USER_RE.test(name)){console.error('Nom d\'utilisateur invalide.');process.exit(1);}
    if(cmd==='create-user'&&DB.users.byName[name]){console.error('Ce compte existe déjà.');process.exit(1);}
    if(cmd==='reset-password'&&!DB.users.byName[name]){console.error('Compte introuvable.');process.exit(1);}
    const pw=await ask('Mot de passe : ',true),prob=passwordProblem(pw,name);if(prob){console.error(prob);process.exit(1);}
    const hash=await hashPassword(pw);
    if(cmd==='create-user'){DB.users.byName[name]={id:DB.users.next++,name,hash,created:Date.now(),admin:flag('--admin')};save('users');console.log('Compte créé :',name);}
    else{DB.users.byName[name].hash=hash;save('users');revokeUser(DB.users.byName[name].id);fails.delete(name);console.log('Mot de passe modifié, toutes les sessions de ce compte sont fermées.');}
  }else if(cmd==='create-invite'){
    const ALPHA='ABCDEFGHJKMNPQRSTUVWXYZ23456789',code=Array.from({length:12},()=>ALPHA[crypto.randomInt(ALPHA.length)]).join(''),uses=parseInt(val('--uses')||'1',10)||1,days=parseInt(val('--days')||'7',10)||7;
    DB.invites[sha(code)]={created:Date.now(),expires:Date.now()+days*86400000,maxUses:uses,uses:0,note:val('--note')||''};save('invites');
    console.log(`Code d'invitation (affiché une seule fois) : ${code}\nUtilisations : ${uses} ; expire dans ${days} jour(s).`);
  }else if(cmd==='list-users'){Object.values(DB.users.byName).forEach(u=>console.log(`${u.id}\t${u.name}\t${u.admin?'admin':'utilisateur'}\t${new Date(u.created).toISOString()}`));}
  else if(cmd==='delete-user'){const u=DB.users.byName[String(args[0]||'').toLowerCase()];if(!u){console.error('Compte introuvable.');process.exit(1);}revokeUser(u.id);delete DB.users.byName[u.name];save('users');console.log('Compte supprimé.');}
  else if(cmd==='revoke-sessions'){const u=DB.users.byName[String(args[0]||'').toLowerCase()];if(!u){console.error('Compte introuvable.');process.exit(1);}revokeUser(u.id);console.log('Sessions fermées.');}
  else{console.error('Commandes : create-user <nom> [--admin] | reset-password <nom> | create-invite [--uses N] [--days N] [--note texte] | list-users | delete-user <nom> | revoke-sessions <nom>');process.exit(1);}
  flushAll();process.exit(0);
}

/* ---------- démarrage ---------- */
async function start(){
  DUMMY=await hashPassword(crypto.randomBytes(18).toString('hex'));
  loadPages();
  const opts=CFG.tlsCert&&CFG.tlsKey?{cert:fs.readFileSync(CFG.tlsCert),key:fs.readFileSync(CFG.tlsKey)}:null;
  const srv=(opts?https.createServer(opts,handle):http.createServer(handle));
  srv.requestTimeout=15000;srv.headersTimeout=10000;srv.keepAliveTimeout=5000;srv.maxHeadersCount=60;
  srv.on('clientError',(e,sock)=>{try{sock.end('HTTP/1.1 400 Bad Request\r\n\r\n');}catch(_){}});
  await new Promise(r=>srv.listen(CFG.port,CFG.host,r));
  const addr=srv.address();log('listening',{url:`${opts?'https':'http'}://${CFG.host}:${addr.port}`,registration:CFG.registration,users:Object.keys(DB.users.byName).length});
  const stop=()=>{flushAll();srv.close(()=>process.exit(0));setTimeout(()=>process.exit(0),2000).unref();};
  process.on('SIGTERM',stop);process.on('SIGINT',stop);
  return srv;
}
if(require.main===module){
  const [cmd,...args]=process.argv.slice(2);
  (cmd?cli(cmd,args):start()).catch(e=>{console.error(e);process.exit(1);});
}
module.exports={start,CFG};
