// Encrypts password-protected pages for GitHub Pages.
// Edit the readable versions in _src/ (gitignored), then run:
//   node lock.mjs 'the-password'
// Each file in _src/ is AES-GCM encrypted and written to the same path in the site.
import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const password = process.argv[2];
if (!password) { console.error("Usage: node lock.mjs 'password'"); process.exit(1); }

const SRC = '_src';
const ITER = 600000;
const subtle = globalThis.crypto.subtle;
const b64 = (buf) => Buffer.from(buf).toString('base64');

function walk(dir) {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : p.endsWith('.html') ? [p] : [];
  });
}

async function encrypt(text) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const base = await subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text));
  return { s: b64(salt), i: b64(iv), c: b64(ct), n: ITER };
}

const gate = (payload) => `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Protected Case Study | Nicholas Womack</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500&family=Open+Sans:wght@400;600&display=swap" rel="stylesheet">
<style>
:root{--ink:#0E1419;--mid:#5A6672;--soft:#8B96A1;--rule:#D6DEE5;--card:#F1F4F7;--accent:#0D4470;--link:#12459B;--err:#B42318}
*{box-sizing:border-box;margin:0}
html,body{height:100%}
body{background:#fff;color:var(--ink);font-family:'Open Sans',system-ui,sans-serif;display:flex;align-items:center;justify-content:center;padding:24px 16px}
.gate{width:100%;max-width:440px}
.label{font-family:'IBM Plex Mono',ui-monospace,monospace;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--soft);margin-bottom:16px;display:flex;align-items:center;gap:8px}
.label svg{flex:none}
h1{font-family:'Archivo',system-ui,sans-serif;font-weight:700;font-size:clamp(1.75rem,5vw,2.25rem);line-height:1.1;letter-spacing:-.02em;margin-bottom:12px}
p{color:var(--mid);font-size:15px;line-height:1.6;margin-bottom:28px}
label{display:block;font-size:13px;font-weight:600;margin-bottom:8px}
.row{display:flex;gap:8px}
input{flex:1;min-width:0;font:inherit;font-size:16px;padding:12px 14px;border:1px solid var(--rule);border-radius:8px;background:var(--card);color:var(--ink);outline:none;transition:border-color .15s,background .15s}
input:focus{border-color:var(--accent);background:#fff}
input[aria-invalid=true]{border-color:var(--err)}
button{font-family:'Archivo',system-ui,sans-serif;font-weight:600;font-size:15px;padding:12px 20px;border:0;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer;transition:background .15s}
button:hover{background:#031C39}
button:disabled{opacity:.6;cursor:wait}
.msg{min-height:20px;margin-top:10px;font-size:13px;color:var(--err)}
.back{display:inline-block;margin-top:28px;font-size:14px;color:var(--link);text-decoration:none}
.back:hover{text-decoration:underline}
</style>
</head>
<body>
<main class="gate">
  <div class="label"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>Chase Payment Solutions</div>
  <h1>This case study is password protected</h1>
  <p>The work shown here is under NDA. Enter the password you were given to view it.</p>
  <form id="f" autocomplete="off">
    <label for="pw">Password</label>
    <div class="row">
      <input id="pw" type="password" autofocus required aria-describedby="msg">
      <button id="go" type="submit">Unlock</button>
    </div>
    <div class="msg" id="msg" role="alert"></div>
  </form>
  <a class="back" href="/">&lsaquo; Back to portfolio</a>
</main>
<script>
(function(){
  var P=${JSON.stringify(payload)}, KEY='nw-protected-pw';
  var f=document.getElementById('f'), pw=document.getElementById('pw'), go=document.getElementById('go'), msg=document.getElementById('msg');
  function u8(s){return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0)})}
  async function open(pass){
    var s=crypto.subtle, base=await s.importKey('raw',new TextEncoder().encode(pass),'PBKDF2',false,['deriveKey']);
    var key=await s.deriveKey({name:'PBKDF2',salt:u8(P.s),iterations:P.n,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['decrypt']);
    var html=new TextDecoder().decode(await s.decrypt({name:'AES-GCM',iv:u8(P.i)},key,u8(P.c)));
    try{sessionStorage.setItem(KEY,pass)}catch(e){}
    document.open();document.write(html);document.close();
  }
  var saved=null; try{saved=sessionStorage.getItem(KEY)}catch(e){}
  if(saved){open(saved).catch(function(){try{sessionStorage.removeItem(KEY)}catch(e){}})}
  f.addEventListener('submit',function(e){
    e.preventDefault(); go.disabled=true; msg.textContent='';
    open(pw.value).catch(function(){
      go.disabled=false; pw.setAttribute('aria-invalid','true'); msg.textContent='That password is not correct. Try again.'; pw.select();
    });
  });
  pw.addEventListener('input',function(){pw.removeAttribute('aria-invalid');msg.textContent=''});
})();
</script>
</body>
</html>
`;

for (const file of walk(SRC)) {
  const out = relative(SRC, file);
  writeFileSync(out, gate(await encrypt(readFileSync(file, 'utf8'))));
  console.log('Locked', out);
}
