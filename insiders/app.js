(() => {
  'use strict';

  // Utilities
  const te = new TextEncoder(), td = new TextDecoder();
  const MAX_CHARS = 250000; // ~250 KB guardrail

  const $ = s => document.querySelector(s);
  const $$ = s => Array.from(document.querySelectorAll(s));

  function str2bytes(s){ return te.encode((s ?? '').normalize('NFKC')); }
  function bytes2str(b){ return td.decode(b); }
  function rand(n){ const a = new Uint8Array(n); crypto.getRandomValues(a); return a; }
  function concatBytes(a,b){ const out = new Uint8Array(a.length + b.length); out.set(a,0); out.set(b,a.length); return out; }

  function ab2b64u(buf){
    const b = new Uint8Array(buf); let bin = ''; const CHUNK = 0x8000;
    for (let i=0;i<b.length;i+=CHUNK){ bin += String.fromCharCode.apply(null, b.subarray(i, i+CHUNK)); }
    return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  }
  function b64u2ab(b64u){
    let b64 = b64u.replace(/-/g,'+').replace(/_/g,'/'); while(b64.length % 4) b64 += '=';
    const bin = atob(b64); const out = new Uint8Array(bin.length);
    for (let i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function invalidate(el){ el.classList.add('invalid'); setTimeout(()=> el.classList.remove('invalid'), 1400); }
  function validateOK(el){ el.classList.add('valid'); setTimeout(()=> el.classList.remove('valid'), 1500); }
  function clearVal(id){ const el = document.getElementById(id); if (el) el.value=''; }

  function setBusy(btn, busy){
    btn.setAttribute('aria-busy', busy ? 'true' : 'false');
    const text = btn.querySelector('.btn-text');
    if (text) {
      const base = btn.getAttribute('data-base-text') || text.textContent || '';
      if (!btn.hasAttribute('data-base-text')) btn.setAttribute('data-base-text', base);
      text.textContent = busy ? (btn.getAttribute('data-busy-text') || 'Working...') : btn.getAttribute('data-base-text');
    }
    btn.disabled = busy;
  }

  function showTip(el){ el.classList.add('show'); setTimeout(()=> el.classList.remove('show'), 1400); }

  // Envelope header (AAD-bound)
  const X4V = 2, LAYERS = 4;
  function buildHeaderPBKDF2(params){
    // x4v2|k=pbkdf2;i=600000;h=SHA-256;alg=AES-GCM;layers=4||
    const hash = (params.hash === 'SHA-512') ? 'SHA-512' : 'SHA-256';
    const iters = Math.min(Math.max(Number(params.iterations||600000), 120000), 1200000);
    return `x4v${X4V}|k=pbkdf2;i=${iters};h=${hash};alg=AES-GCM;layers=${LAYERS}||`;
  }
  function parseHeader(text){
    if (!text.startsWith('x4v') || text.indexOf('||')===-1) return null;
    const sep = text.indexOf('||'); const header = text.slice(0, sep); const payload = text.slice(sep+2);
    const [ver, kvs] = header.split('|'); if (!ver || !kvs) return null;
    const vnum = Number(ver.replace('x4v',''));
    const map = {}; kvs.split(';').forEach(kv => { const [k,v]=kv.split('='); map[k]=v; });
    if (map.k !== 'pbkdf2') return null;
    const iterations = Math.min(Math.max(Number(map.i||600000),120000),1200000);
    const hash = (map.h === 'SHA-512') ? 'SHA-512' : 'SHA-256';
    return { version:vnum, header, payload, params:{ iterations, hash } };
  }

  // PBKDF2 (password -> key)
  async function derivePBKDF2(password, salt, ctx, iterations=600000, hash='SHA-256'){
    const material = await crypto.subtle.importKey('raw', str2bytes(password), 'PBKDF2', false, ['deriveKey']);
    // Domain separation: salt || '|' || ctx
    const saltWithInfo = concatBytes(salt, str2bytes('|'+ctx));
    return crypto.subtle.deriveKey(
      { name:'PBKDF2', salt: saltWithInfo, iterations, hash },
      material,
      { name:'AES-GCM', length:256 },
      false,
      ['encrypt','decrypt']
    );
  }

  // AES-GCM layer ops (AAD-bound with header)
  async function encLayer(dataInput, password, params, ctx, aadBytes){
    const salt = rand(16), iv = rand(12);
    const key = await derivePBKDF2(password, salt, ctx, params.iterations, params.hash);
    const plain = (dataInput instanceof ArrayBuffer || ArrayBuffer.isView(dataInput)) ? (dataInput.buffer || dataInput) : str2bytes(String(dataInput));
    const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv, additionalData: aadBytes }, key, plain);
    const out = new Uint8Array(salt.length + iv.length + ct.byteLength);
    out.set(salt,0); out.set(iv, salt.length); out.set(new Uint8Array(ct), salt.length+iv.length);
    return out.buffer;
  }
  async function decLayer(buf, password, params, ctx, aadBytes){
    const bytes = new Uint8Array(buf);
    const salt = bytes.slice(0,16), iv = bytes.slice(16,28), ct = bytes.slice(28);
    const key = await derivePBKDF2(password, salt, ctx, params.iterations, params.hash);
    return crypto.subtle.decrypt({ name:'AES-GCM', iv, additionalData: aadBytes }, key, ct);
  }

  async function quadEncrypt(plaintext, p1, p2, params, aadBytes){
    let l = await encLayer(plaintext, p1, params, 'layer1', aadBytes);
    l = await encLayer(l,        p1, params, 'layer2', aadBytes);
    l = await encLayer(l,        p2, params, 'layer3', aadBytes);
    l = await encLayer(l,        p2, params, 'layer4', aadBytes);
    p1=''; p2=''; return l;
  }
  async function quadDecrypt(b64u, p1, p2, params, aadBytes){
    try{
      let l = b64u2ab(b64u);
      l = await decLayer(l, p2, params, 'layer4', aadBytes);
      l = await decLayer(l, p2, params, 'layer3', aadBytes);
      l = await decLayer(l, p1, params, 'layer2', aadBytes);
      l = await decLayer(l, p1, params, 'layer1', aadBytes);
      p1=''; p2=''; return bytes2str(l);
    }catch(e){ console.error('Decrypt failed', e); return null; }
  }

  // Calibrate PBKDF2 (~300ms target)
  async function calibratePBKDF2(targetMs=300){
    const salt = rand(16);
    const mat = await crypto.subtle.importKey('raw', str2bytes('x4-cal'), 'PBKDF2', false, ['deriveBits']);
    let it = 150000; let dt = 0;
    while (it <= 1200000){
      const t0 = performance.now();
      await crypto.subtle.deriveBits({name:'PBKDF2', salt, iterations:it, hash:'SHA-256'}, mat, 256);
      dt = performance.now()-t0; if (dt >= targetMs*0.9) break;
      it = Math.floor(it*1.5);
    }
    return Math.min(Math.max(it, 120000), 1200000);
  }

  // Tabs
  function showEnc(){
    $('#tab-enc').classList.add('active'); $('#tab-dec').classList.remove('active');
    $('#tab-enc').setAttribute('aria-selected','true'); $('#tab-dec').setAttribute('aria-selected','false');
    $('#sec-enc').classList.remove('hidden'); $('#sec-dec').classList.add('hidden'); $('#enc-msg').focus();
  }
  function showDec(){
    $('#tab-dec').classList.add('active'); $('#tab-enc').classList.remove('active');
    $('#tab-dec').setAttribute('aria-selected','true'); $('#tab-enc').setAttribute('aria-selected','false');
    $('#sec-dec').classList.remove('hidden'); $('#sec-enc').classList.add('hidden'); $('#dec-in').focus();
  }

  // Init
  window.addEventListener('DOMContentLoaded', () => {
    // Only Encrypt visible at load
    showEnc();
    $('#tab-enc').addEventListener('click', showEnc);
    $('#tab-dec').addEventListener('click', showDec);

    // Eye toggles
    $$('.eye').forEach(b=> b.addEventListener('click', ()=> {
      const id = b.getAttribute('data-for'); const i = document.getElementById(id);
      if (!i) return; i.type = (i.type==='password') ? 'text' : 'password';
    }));

    // Calibrate PBKDF2
    $('#pbkdf2-cal').addEventListener('click', async (ev)=>{
      const btn = ev.currentTarget;
      setBusy(btn, true);
      try{
        const it = await calibratePBKDF2(300);
        $('#pbkdf2-iters').value = it;
        validateOK($('#pbkdf2-iters'));
      }catch(e){ console.warn('Calibration failed', e); invalidate($('#pbkdf2-iters')); }
      finally{ setBusy(btn, false); }
    });

    // Copy buttons
    $('#copy-enc').addEventListener('click', async ()=>{
      const v = $('#enc-out').value.trim(); if (!v) return;
      try{ await navigator.clipboard.writeText(v); showTip($('#tip-enc')); }catch(e){ console.warn('Clipboard failed', e); }
    });
    $('#copy-dec').addEventListener('click', async ()=>{
      const v = $('#dec-out').value.trim(); if (!v) return;
      try{ await navigator.clipboard.writeText(v); showTip($('#tip-dec')); }catch(e){ console.warn('Clipboard failed', e); }
    });

    // Encrypt
    $('#btn-enc').addEventListener('click', async (ev)=>{
      const btn = ev.currentTarget;
      const msg = $('#enc-msg'), p1 = $('#enc-p1'), p2 = $('#enc-p2'), out = $('#enc-out');
      [msg,p1,p2,out].forEach(x=> x.classList.remove('invalid','valid'));

      if (!msg.value.trim()) { invalidate(msg); return; }
      if (!p1.value.trim()) { invalidate(p1); return; }
      if (!p2.value.trim()) { invalidate(p2); return; }
      if (msg.value.length > MAX_CHARS){ invalidate(msg); return; }

      const iterations = Math.min(Math.max(Number($('#pbkdf2-iters').value||600000),120000),1200000);
      const hashRaw = $('#pbkdf2-hash').value;
      const hash = (hashRaw === 'SHA-512') ? 'SHA-512' : 'SHA-256';

      const params = { iterations, hash };
      const header = buildHeaderPBKDF2(params);
      const aad = str2bytes(header);

      setBusy(btn, true);
      try{
        const buf = await quadEncrypt(msg.value, p1.value, p2.value, params, aad);
        out.value = header + ab2b64u(buf);
        validateOK(out); // green on success
      }catch(e){ console.error(e); invalidate(out); }
      finally{
        $('#enc-p1').value=''; $('#enc-p2').value='';
        setBusy(btn, false);
      }
    });

    // Header detection
    function showDetected(text){
      const det = $('#kdf-detected');
      const parsed = parseHeader(text.trim());
      det.textContent = parsed ? `Detected: PBKDF2 (i=${parsed.params.iterations}, ${parsed.params.hash})` : '';
    }
    $('#dec-in').addEventListener('input', ()=> showDetected($('#dec-in').value));

    // Decrypt
    $('#btn-dec').addEventListener('click', async (ev)=>{
      const btn = ev.currentTarget;
      const txt = $('#dec-in'), p1 = $('#dec-p1'), p2 = $('#dec-p2'), out = $('#dec-out');
      [txt,p1,p2,out].forEach(x=> x.classList.remove('invalid','valid'));

      if (!txt.value.trim()) { invalidate(txt); return; }
      if (!p1.value.trim()) { invalidate(p1); return; }
      if (!p2.value.trim()) { invalidate(p2); return; }

      setBusy(btn, true);
      try{
        const input = txt.value.trim();
        let header, payload, params, aad;

        const parsed = parseHeader(input);
        if (parsed && parsed.version === X4V){
          header = parsed.header + '||';
          payload = parsed.payload;
          params = parsed.params;
          aad = str2bytes(header);
        } else {
          // Legacy (no header): assume PBKDF2 defaults and build AAD from them
          payload = input;
          params = { iterations:600000, hash:'SHA-256' };
          header = buildHeaderPBKDF2(params);
          aad = str2bytes(header);
        }

        const plain = await quadDecrypt(payload, p1.value, p2.value, params, aad);
        if (plain === null){
          out.value = 'Decryption failed. Check passwords and ensure header/ciphertext is intact.';
          invalidate(out); // red on failure
        } else {
          out.value = plain;
          validateOK(out); // green on success
        }
      }catch(e){ console.error(e); out.value='Decryption failed.'; invalidate(out); }
      finally{
        $('#dec-p1').value=''; $('#dec-p2').value='';
        setBusy(btn, false);
      }
    });

    // Clear
    $('#btn-enc-clear').addEventListener('click', ()=>{ clearVal('enc-msg'); clearVal('enc-p1'); clearVal('enc-p2'); clearVal('enc-out'); });
    $('#btn-dec-clear').addEventListener('click', ()=>{ clearVal('dec-in'); clearVal('dec-p1'); clearVal('dec-p2'); clearVal('dec-out'); $('#kdf-detected').textContent=''; });

    if (!window.crypto?.subtle){ alert('WebCrypto not available. Use a modern browser over HTTPS.'); }
  });
})();
