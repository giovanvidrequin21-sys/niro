'use strict';
/* Tests de sécurité : lancent de vrais serveurs et les attaquent par HTTP.  Usage : node tests/auth-tests.js */
const {spawn,spawnSync,execFileSync}=require('node:child_process'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http'),https=require('node:https');
const ROOT=path.resolve(__dirname,'..'),SERVER=path.join(ROOT,'server.js');
let pass=0,fail=0;const failures=[];
const ok=(c,m,extra)=>{if(c){pass++;console.log('  ok  '+m);}else{fail++;failures.push(m);console.log('  ECHEC  '+m+(extra!==undefined?'  → '+JSON.stringify(extra):''));}};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const PW='Correct-horse-battery-9',PW2='Une-autre-phrase-longue-7';
function mkEnv(extra,dir){return {...process.env,QUIET:'1',DATA_DIR:dir,HOST:'127.0.0.1',SCRYPT_N:'16384',...extra};}   // N réduit : tests plus rapides ; la valeur par défaut est 32768
async function startServer(extra={},dir){
  dir=dir||fs.mkdtempSync(path.join(os.tmpdir(),'atelier-'));
  const port=40000+Math.floor(Math.random()*9000),env=mkEnv({PORT:String(port),QUIET:'0',...extra},dir);
  const proc=spawn('node',[SERVER],{env,stdio:['ignore','pipe','pipe']});
  await new Promise((res,rej)=>{const t=setTimeout(()=>rej(new Error('démarrage trop long')),8000);proc.stdout.on('data',d=>{if(String(d).includes('listening')){clearTimeout(t);res();}});proc.stderr.on('data',d=>{process.stderr.write(d);});proc.on('exit',c=>rej(new Error('arrêt '+c)));});
  const tls=!!extra.TLS_CERT;
  return {port,dir,base:`${tls?'https':'http'}://127.0.0.1:${port}`,proc,stop:()=>new Promise(r=>{proc.removeAllListeners('exit');proc.on('exit',r);proc.kill('SIGTERM');})};
}
const cli=(dir,args,input,extra)=>spawnSync('node',[SERVER,...args],{env:mkEnv(extra||{},dir),input,encoding:'utf8'});
const J={'Content-Type':'application/json','X-Requested-With':'fetch'};
const post=(s,p,body,headers={})=>fetch(s.base+p,{method:'POST',redirect:'manual',headers:{...J,...headers},body:JSON.stringify(body)});
const get=(s,p,headers={})=>fetch(s.base+p,{redirect:'manual',headers});
const cookieOf=r=>{const c=(r.headers.getSetCookie?r.headers.getSetCookie():[]).find(x=>/^(__Host-)?sid=/.test(x));return c?c.split(';')[0]:null;};
const setCookieOf=r=>(r.headers.getSetCookie?r.headers.getSetCookie():[]).find(x=>/^(__Host-)?sid=/.test(x))||'';
async function login(s,u,p){const r=await post(s,'/api/login',{username:u,password:p});return {r,cookie:cookieOf(r)};}
const raw=(s,p)=>new Promise((res,rej)=>{const m=s.base.startsWith('https')?https:http;const q=m.request({host:'127.0.0.1',port:s.port,path:p,method:'GET',rejectUnauthorized:false},r=>{let b='';r.on('data',d=>b+=d);r.on('end',()=>res({status:r.statusCode,body:b,headers:r.headers}));});q.on('error',rej);q.end();});
const median=a=>a.sort((x,y)=>x-y)[Math.floor(a.length/2)];

(async()=>{
  /* ============ instance principale : inscription sur invitation ============ */
  const S=await startServer({REGISTRATION:'invite',LOCK_AFTER_FAILURES:'5',IP_AUTH_LIMIT:'100',IP_ANY_LIMIT:'1000'});
  const c1=cli(S.dir,['create-user','admin1','--admin'],PW+'\n');ok(c1.status===0,'création d\'un compte en ligne de commande',c1.stderr);
  const inv=cli(S.dir,['create-invite','--uses','1','--days','1'],'');const code=(inv.stdout.match(/: ([A-Z0-9]{12})/)||[])[1];ok(!!code,'création d\'un code d\'invitation à usage unique');
  const bad=cli(S.dir,['create-user','xy'],PW+'\n');ok(bad.status!==0,'nom d\'utilisateur trop court refusé en ligne de commande');
  const weakCli=cli(S.dir,['create-user','bob123'],'court\n');ok(weakCli.status!==0,'mot de passe faible refusé en ligne de commande');

  console.log('\n— Protection des pages (sans connexion) —');
  let r=await get(S,'/');ok(r.status===302&&r.headers.get('location')==='/login','GET / sans session : redirection vers /login',[r.status,r.headers.get('location')]);
  let body=await r.text();ok(body==='','la redirection ne contient aucune ligne du site');
  r=await get(S,'/index.html');ok(r.status===302&&r.headers.get('location')==='/login','GET /index.html sans session : redirection');
  r=await get(S,'/api/me');ok(r.status===401,'GET /api/me sans session : 401');
  r=await get(S,'/login');body=await r.text();ok(r.status===200&&body.includes('id="f-login"'),'la page de connexion est servie');
  ok(!body.includes('const SYM')&&!body.includes('SYM.find')&&!body.includes('KBFX'),'la page de connexion ne contient pas le code du site');
  for(const p of ['/../server.js','/%2e%2e/server.js','/site/index.html','/data/users.json','/server.js','/tests/auth-tests.js','/..%2fdata%2fusers.json','/%00','/login/../data/users.json','//etc/passwd']){const x=await raw(S,p);ok(![200].includes(x.status)||x.body.includes('f-login'),'chemin « '+p+' » ne divulgue rien',[x.status,x.body.slice(0,40)]);ok(!x.body.includes('scrypt$')&&!x.body.includes('createServer')&&!x.body.includes('const SYM'),'  … et le contenu renvoyé est sans danger');}

  console.log('\n— En-têtes de sécurité —');
  r=await get(S,'/login');const h=r.headers;
  ok(/script-src 'nonce-[A-Za-z0-9+/=]+'/.test(h.get('content-security-policy')||''),'CSP avec jeton à usage unique');
  ok(!/unsafe-inline[^;]*script|script-src[^;]*unsafe/.test(h.get('content-security-policy')||''),'aucun « unsafe-inline » ni « unsafe-eval » pour les scripts');
  ok(/frame-ancestors 'none'/.test(h.get('content-security-policy')||'')&&h.get('x-frame-options')==='DENY','protection contre l\'intégration dans une page tierce');
  ok(h.get('x-content-type-options')==='nosniff'&&h.get('referrer-policy')==='no-referrer'&&/no-store/.test(h.get('cache-control')||''),'nosniff, referrer-policy, cache no-store');
  const nonce1=(await r.text()).match(/nonce="([^"]+)"/)[1];const nonce2=(await (await get(S,'/login')).text()).match(/nonce="([^"]+)"/)[1];ok(nonce1!==nonce2,'le jeton CSP change à chaque réponse');
  r=await get(S,'/introuvable');ok(r.status===404&&r.headers.get('x-content-type-options')==='nosniff','les erreurs portent aussi les en-têtes de sécurité');

  console.log('\n— Connexion —');
  const t0=[],t1=[];
  for(let i=0;i<3;i++){let a=Date.now();await post(S,'/api/login',{username:'inconnu'+i,password:'x'.repeat(12)});t0.push(Date.now()-a);a=Date.now();await post(S,'/api/login',{username:'admin1',password:'faux-mot-de-passe-'+i});t1.push(Date.now()-a);}
  const rU=await post(S,'/api/login',{username:'fantome',password:'whatever-long-1'}),rW=await post(S,'/api/login',{username:'admin1',password:'wrong-password-long'});
  const bU=await rU.json(),bW=await rW.json();
  ok(rU.status===401&&rW.status===401&&bU.error===bW.error,'même réponse pour un compte inconnu et un mauvais mot de passe (pas d\'énumération)',[bU,bW]);
  const mu=median(t0),mw=median(t1);ok(Math.abs(mu-mw)<Math.max(60,mw*0.6),'temps de réponse comparable (inconnu '+mu+' ms, faux mot de passe '+mw+' ms)');
  r=await post(S,'/api/login',{username:'admin1',password:''});ok(r.status===400,'champs vides : 400');
  let L=await login(S,'admin1',PW);ok(L.r.status===200&&!!L.cookie,'connexion valide : 200 et cookie de session');
  const sc=setCookieOf(L.r);ok(/HttpOnly/i.test(sc)&&/SameSite=Strict/i.test(sc)&&/Path=\//.test(sc)&&/Max-Age=\d+/.test(sc),'cookie : HttpOnly, SameSite=Strict, Path=/, Max-Age',sc);
  ok(!/Secure/i.test(sc),'cookie sans « Secure » en HTTP simple (mode auto) : attendu en test local');
  ok((L.cookie.split('=')[1]||'').length===43,'jeton de 256 bits (43 caractères base64url)');
  const adminCookie=L.cookie;
  r=await get(S,'/',{cookie:adminCookie});body=await r.text();
  ok(r.status===200&&body.includes('window.__SESSION__=')&&body.includes('"name":"admin1"'),'GET / avec session : le site est servi avec la session injectée');
  const nonce=r.headers.get('content-security-policy').match(/'nonce-([^']+)'/)[1];
  const tags=[...body.matchAll(/<script([^>]*)>/g)].map(m=>m[1]);ok(tags.length>=2&&tags.every(t=>t.includes('nonce="'+nonce+'"')),'tous les scripts du site portent le jeton CSP',tags);
  ok(/no-store/.test(r.headers.get('cache-control')),'le site est servi en « no-store »');
  ok(body.includes('id="acct"')&&body.includes('<title>'),'le site contient bien l\'application');
  r=await get(S,'/api/me',{cookie:adminCookie});const me=await r.json();ok(r.status===200&&me.name==='admin1'&&me.admin===true,'GET /api/me avec session');
  r=await get(S,'/login',{cookie:adminCookie});ok(r.status===302&&r.headers.get('location')==='/','/login avec session : redirigé vers le site');

  console.log('\n— Jetons falsifiés —');
  const tok=adminCookie.split('=')[1];
  for(const [n,v] of [['un caractère modifié',tok.slice(0,-1)+(tok.slice(-1)==='A'?'B':'A')],['jeton vide',''],['jeton tronqué',tok.slice(0,10)],['jeton très long','A'.repeat(1000)],['jeton avec caractères spéciaux','"><script>alert(1)</script>'],['jeton d\'un autre format','Bearer '+tok]]){
    const x=await get(S,'/api/me',{cookie:'sid='+v});const y=await get(S,'/',{cookie:'sid='+v});ok(x.status===401&&y.status===302,'cookie falsifié refusé : '+n);}
  const m=await get(S,'/api/me',{cookie:'__Host-sid='+tok});ok(m.status===200,'(information) le nom de cookie préfixé est aussi accepté');

  console.log('\n— Anti-CSRF —');
  r=await fetch(S.base+'/api/login',{method:'POST',headers:{...J,Origin:'https://evil.example'},body:JSON.stringify({username:'admin1',password:PW})});ok(r.status===403,'origine étrangère refusée');
  r=await fetch(S.base+'/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'admin1',password:PW})});ok(r.status===403,'sans en-tête X-Requested-With : refusé');
  r=await fetch(S.base+'/api/login',{method:'POST',headers:{'Content-Type':'text/plain','X-Requested-With':'fetch'},body:JSON.stringify({username:'admin1',password:PW})});ok(r.status===403,'Content-Type « text/plain » (formulaire croisé) refusé');
  r=await fetch(S.base+'/api/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-Requested-With':'fetch'},body:'username=admin1&password='+PW});ok(r.status===403,'formulaire classique refusé');
  r=await fetch(S.base+'/api/logout',{method:'POST',headers:{...J,'Sec-Fetch-Site':'cross-site',cookie:adminCookie},body:'{}'});ok(r.status===403,'Sec-Fetch-Site cross-site refusé');
  r=await fetch(S.base+'/api/logout',{method:'POST',headers:{...J,Origin:S.base,cookie:adminCookie},body:'{}'});ok(r.status===200,'même origine acceptée (déconnexion)');
  r=await get(S,'/api/me',{cookie:adminCookie});ok(r.status===401,'après déconnexion, l\'ancien jeton est révoqué côté serveur');
  for(const [meth,p] of [['PUT','/api/login'],['DELETE','/api/me'],['GET','/api/login'],['GET','/api/logout']]){const x=await fetch(S.base+p,{method:meth,redirect:'manual'});ok(x.status===405,`${meth} ${p} : 405`,x.status);}

  console.log('\n— Corps de requête —');
  r=await fetch(S.base+'/api/login',{method:'POST',headers:J,body:'{pas du json'});ok(r.status===400,'JSON invalide : 400');
  r=await fetch(S.base+'/api/login',{method:'POST',headers:J,body:JSON.stringify({username:'a'.repeat(9000),password:'b'})}).catch(e=>({status:'coupée'}));ok(r.status===413||r.status==='coupée','corps de plus de 4 Ko : refusé',r.status);
  r=await get(S,'/healthz');ok(r.status===200,'le serveur reste disponible après ces requêtes');
  r=await post(S,'/api/login',{username:{$ne:1},password:{$ne:1}});ok(r.status===400||r.status===401,'valeurs non textuelles (injection de type) : refusées proprement',r.status);

  console.log('\n— Verrouillage et limitation —');
  for(let i=0;i<5;i++)await post(S,'/api/login',{username:'admin1',password:'mauvais-mot-de-passe-'+i});
  r=await post(S,'/api/login',{username:'admin1',password:PW});ok(r.status===429&&!!r.headers.get('retry-after'),'après 5 échecs, même le bon mot de passe est refusé (429 + Retry-After)',r.status);
  for(let i=0;i<5;i++)await post(S,'/api/login',{username:'inexistant99',password:'mauvais-mot-de-passe-'+i});
  r=await post(S,'/api/login',{username:'inexistant99',password:'autre-mot-de-passe-1'});ok(r.status===429,'un compte inexistant est « verrouillé » de la même façon (aucune différence observable)');

  console.log('\n— Inscription (mode invitation) —');
  r=await post(S,'/api/register',{username:'alice01',password:PW});ok(r.status===403,'sans code d\'invitation : refusé');
  r=await post(S,'/api/register',{username:'alice01',password:PW,invite:'FAUXCODE1234'});ok(r.status===403,'faux code d\'invitation : refusé');
  const reg=async(u,p,i)=>post(S,'/api/register',{username:u,password:p,invite:i});
  r=await reg('Al ice',PW,code);ok(r.status===400,'nom d\'utilisateur avec espace : refusé');
  r=await reg('al',PW,code);ok(r.status===400,'nom d\'utilisateur trop court : refusé');
  r=await reg('alice01','court1',code);ok(r.status===400,'mot de passe trop court : refusé');
  r=await reg('alice01','password123',code);ok(r.status===400,'mot de passe courant : refusé');
  r=await reg('alice01','aaaaaaaaaaaaaa',code);ok(r.status===400,'mot de passe répétitif : refusé');
  r=await reg('alice01','mon-alice01-secret',code);ok(r.status===400,'mot de passe contenant le nom d\'utilisateur : refusé');
  r=await reg('admin1',PW2,code);ok(r.status===409,'nom déjà pris : 409');
  r=await reg('alice01',PW2,code);const aliceCookie=cookieOf(r);ok(r.status===201&&!!aliceCookie,'inscription valide : 201 et connexion automatique');
  r=await get(S,'/',{cookie:aliceCookie});ok(r.status===200,'le nouveau compte accède au site');
  r=await reg('bob0001',PW2,code);ok(r.status===403,'le code d\'invitation à usage unique est épuisé');
  r=await post(S,'/api/register',{username:'bob0001',password:PW2,invite:{x:1}});ok(r.status===403||r.status===400,'code d\'invitation de type invalide : refusé');
  const exp=cli(S.dir,['create-invite','--uses','1','--days','1'],'');await sleep(300);
  ok((await login(S,'alice01',PW2)).r.status===200,'une commande en ligne de commande n\'efface pas un compte créé juste avant par le serveur (non-régression)');
  cli(S.dir,['revoke-sessions','admin1'],'');cli(S.dir,['list-users'],'');await sleep(300);
  ok((await login(S,'alice01',PW2)).r.status===200,'idem après plusieurs commandes successives');

  console.log('\n— Stockage —');
  await sleep(500);
  const all=fs.readdirSync(S.dir).map(f=>fs.readFileSync(path.join(S.dir,f),'utf8')).join('\n');
  ok(!all.includes(PW)&&!all.includes(PW2),'aucun mot de passe en clair dans les fichiers de données');
  ok(/"hash":"scrypt\$16384\$8\$1\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+"/.test(all),'mots de passe stockés avec scrypt, sel et paramètres');
  ok(!all.includes(adminCookie.split('=')[1])&&!all.includes(aliceCookie.split('=')[1]),'aucun jeton de session en clair (seulement leur hash)');
  ok(!all.includes(code),'le code d\'invitation n\'est stocké que haché');
  const users=JSON.parse(fs.readFileSync(path.join(S.dir,'users.json'),'utf8'));const salts=Object.values(users.byName).map(u=>u.hash.split('$')[4]);ok(new Set(salts).size===salts.length,'un sel différent par compte');
  ok((fs.statSync(S.dir).mode&0o077)===0,'dossier de données en 0700');ok(fs.readdirSync(S.dir).filter(f=>f.endsWith('.json')).every(f=>(fs.statSync(path.join(S.dir,f)).mode&0o077)===0),'fichiers de données en 0600');

  console.log('\n— Changement de mot de passe —');
  L=await login(S,'alice01',PW2);const sessA=L.cookie;const sessB=(await login(S,'alice01',PW2)).cookie;ok(!!sessA&&!!sessB&&sessA!==sessB,'deux sessions ouvertes pour le même compte');
  r=await fetch(S.base+'/api/change-password',{method:'POST',headers:{...J,cookie:sessA},body:JSON.stringify({current:'faux-actuel-123',new:PW})});ok(r.status===403,'ancien mot de passe faux : refusé');
  r=await fetch(S.base+'/api/change-password',{method:'POST',headers:{...J,cookie:sessA},body:JSON.stringify({current:PW2,new:'court'})});ok(r.status===400,'nouveau mot de passe faible : refusé');
  r=await fetch(S.base+'/api/change-password',{method:'POST',headers:J,body:JSON.stringify({current:PW2,new:PW})});ok(r.status===401,'sans session : refusé');
  r=await fetch(S.base+'/api/change-password',{method:'POST',headers:{...J,cookie:sessA},body:JSON.stringify({current:PW2,new:PW})});const newA=cookieOf(r);ok(r.status===200&&!!newA,'changement valide : nouvelle session émise');
  ok((await get(S,'/api/me',{cookie:sessB})).status===401&&(await get(S,'/api/me',{cookie:sessA})).status===401,'toutes les anciennes sessions sont révoquées');
  ok((await get(S,'/api/me',{cookie:newA})).status===200,'la nouvelle session fonctionne');
  ok((await login(S,'alice01',PW2)).r.status===401&&(await login(S,'alice01',PW)).r.status===200,'l\'ancien mot de passe ne marche plus, le nouveau oui');

  console.log('\n— Fixation de session —');
  r=await fetch(S.base+'/api/login',{method:'POST',headers:{...J,cookie:'sid=jeton-impose-par-un-attaquant-0000000000000000000'},body:JSON.stringify({username:'alice01',password:PW})});const fresh=cookieOf(r);ok(r.status===200&&fresh&&!fresh.includes('jeton-impose'),'un jeton imposé n\'est jamais adopté : nouveau jeton émis');

  console.log('\n— Ligne de commande pendant que le serveur tourne —');
  cli(S.dir,['create-user','cli0001'],PW+'\n');await sleep(700);
  let cc=await login(S,'cli0001',PW);ok(cc.r.status===200,'un compte créé en ligne de commande est utilisable sans redémarrer le serveur');
  const before=await get(S,'/api/me',{cookie:cc.cookie});cli(S.dir,['revoke-sessions','cli0001'],'');await sleep(700);
  ok(before.status===200&&(await get(S,'/api/me',{cookie:cc.cookie})).status===401,'« revoke-sessions » ferme les sessions d\'un serveur en marche');
  cc=await login(S,'cli0001',PW);cli(S.dir,['reset-password','cli0001'],PW2+'\n');await sleep(700);
  ok((await get(S,'/api/me',{cookie:cc.cookie})).status===401&&(await login(S,'cli0001',PW)).r.status===401&&(await login(S,'cli0001',PW2)).r.status===200,'« reset-password » change le mot de passe et ferme les sessions');
  cli(S.dir,['delete-user','cli0001'],'');await sleep(700);ok((await login(S,'cli0001',PW2)).r.status===401,'« delete-user » supprime le compte');
  ok((await login(S,'alice01',PW)).r.status===200,'les autres comptes ne sont pas affectés (rien n\'a été écrasé)');

  console.log('\n— Redémarrage —');
  const keep=(await login(S,'alice01',PW)).cookie;await S.stop();
  const S2=await startServer({REGISTRATION:'invite'},S.dir);
  r=await get(S2,'/api/me',{cookie:keep});ok(r.status===200,'une session valide survit à un redémarrage du serveur');
  r=await get(S2,'/api/me',{cookie:adminCookie});ok(r.status===401,'une session révoquée reste révoquée après redémarrage');
  await S2.stop();

  /* ============ autres modes d'inscription ============ */
  console.log('\n— Modes d\'inscription —');
  const SC=await startServer({REGISTRATION:'closed'});r=await post(SC,'/api/register',{username:'zed0001',password:PW});ok(r.status===403,'mode fermé : inscription refusée');await SC.stop();
  const SO=await startServer({REGISTRATION:'open'});r=await post(SO,'/api/register',{username:'zed0001',password:PW});ok(r.status===201,'mode ouvert : inscription sans code');
  r=await get(SO,'/login');ok((await r.text()).includes('{"registration":"open"}'),'la page de connexion reçoit le mode d\'inscription');await SO.stop();

  console.log('\n— Inscriptions par adresse IP —');
  const SR=await startServer({REGISTRATION:'open',REG_PER_IP_PER_HOUR:'3'});const rc=[];for(let i=0;i<5;i++){rc.push((await post(SR,'/api/register',{username:'spam'+i+'abc',password:PW})).status);}
  ok(rc.slice(0,3).every(c=>c===201)&&rc.slice(3).every(c=>c===429),'les inscriptions sont limitées par adresse IP et par heure',rc);await SR.stop();
  console.log('\n— Les connexions réussies ne bloquent pas une adresse partagée —');
  const SP=await startServer({REGISTRATION:'open',IP_AUTH_LIMIT:'4'});await post(SP,'/api/register',{username:'foyer01',password:PW});const okc=[];for(let i=0;i<12;i++)okc.push((await login(SP,'foyer01',PW)).r.status);
  ok(okc.every(c=>c===200),'12 connexions réussies de suite depuis la même adresse : aucune n\'est bloquée (seuls les échecs comptent)',okc);await SP.stop();

  /* ============ limitation par adresse IP ============ */
  console.log('\n— Limitation par adresse IP —');
  const SI=await startServer({REGISTRATION:'open',IP_AUTH_LIMIT:'6'});let codes=[];for(let i=0;i<9;i++){const x=await post(SI,'/api/login',{username:'u'+i+'abcd',password:'mot-de-passe-long-'+i});codes.push(x.status);}
  ok(codes.slice(0,6).every(c=>c===401)&&codes.slice(6).every(c=>c===429),'au-delà de la limite, toutes les tentatives (comptes différents) sont bloquées',codes);await SI.stop();

  /* ============ expirations ============ */
  console.log('\n— Expiration des sessions —');
  const SE=await startServer({REGISTRATION:'open',SESSION_IDLE_SECONDS:'2'});await post(SE,'/api/register',{username:'idle001',password:PW});
  const ie=(await login(SE,'idle001',PW)).cookie;ok((await get(SE,'/api/me',{cookie:ie})).status===200,'session active');await sleep(1200);ok((await get(SE,'/api/me',{cookie:ie})).status===200,'l\'activité prolonge la session');await sleep(2600);
  ok((await get(SE,'/api/me',{cookie:ie})).status===401&&(await get(SE,'/',{cookie:ie})).status===302,'inactivité : session expirée côté serveur');await SE.stop();
  const SA=await startServer({REGISTRATION:'open',SESSION_MAX_SECONDS:'2'});await post(SA,'/api/register',{username:'abs001',password:PW});const ac=(await login(SA,'abs001',PW)).cookie;
  for(let i=0;i<3;i++){await sleep(900);await get(SA,'/api/me',{cookie:ac});}ok((await get(SA,'/api/me',{cookie:ac})).status===401,'durée maximale : la session expire même si elle est utilisée en continu');await SA.stop();

  console.log('\n— Nombre de sessions par compte —');
  const SM=await startServer({REGISTRATION:'open',MAX_SESSIONS_PER_USER:'3'});await post(SM,'/api/register',{username:'multi01',password:PW});const cs=[];for(let i=0;i<4;i++)cs.push((await login(SM,'multi01',PW)).cookie);
  ok((await get(SM,'/api/me',{cookie:cs[0]})).status===401&&(await get(SM,'/api/me',{cookie:cs[3]})).status===200,'la plus ancienne session est fermée au-delà de la limite');await SM.stop();

  /* ============ HTTPS ============ */
  console.log('\n— HTTPS —');
  const cd=fs.mkdtempSync(path.join(os.tmpdir(),'cert-'));
  try{execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',path.join(cd,'k.pem'),'-out',path.join(cd,'c.pem'),'-days','1','-subj','/CN=localhost'],{stdio:'ignore'});
    process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';
    const ST=await startServer({REGISTRATION:'open',TLS_CERT:path.join(cd,'c.pem'),TLS_KEY:path.join(cd,'k.pem')});
    r=await post(ST,'/api/register',{username:'tls0001',password:PW});const sct=setCookieOf(r);
    ok(r.status===201&&/^__Host-sid=/.test(sct)&&/;\s*Secure/i.test(sct)&&/HttpOnly/i.test(sct)&&/SameSite=Strict/i.test(sct),'en HTTPS : cookie « __Host-sid », Secure, HttpOnly, SameSite=Strict',sct);
    ok(/max-age=\d+/.test(r.headers.get('strict-transport-security')||''),'en-tête HSTS présent en HTTPS');
    r=await get(ST,'/',{cookie:cookieOf(r)});ok(r.status===200,'le site est servi en HTTPS avec la session');await ST.stop();
  }catch(e){ok(false,'test HTTPS impossible : '+e.message);}

  console.log(`\n${pass} vérifications réussies, ${fail} échec(s).`);if(fail)console.log('Échecs :\n - '+failures.join('\n - '));
  await S.stop().catch(()=>{});process.exit(fail?1:0);
})().catch(e=>{console.error('ERREUR DES TESTS',e);process.exit(2);});
