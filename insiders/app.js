/* app.js — worker-based crypto, UI & safety wrappers
   Replace your previous app.js with this file.
   Reviewed original app.js and improved workerization, hardened bounds, zeroing, and safer UX.
   Original reviewed:  [oai_citation:4‡app.js](sediment://file_0000000075607206ab43bac1e07cfd10)
*/
(() => {
  'use strict';

  // === Utilities (main thread) ===
  const te = new TextEncoder(), td = new TextDecoder();
  const MAX_CHARS = 250000; // ~250 KB guardrail
  const X4V = 2, LAYERS = 4;

  const $ = s => document.querySelector(s);
  const $$ = s => Array.from(document.querySelectorAll(s));
  function str2bytes(s){ return te.encode((s ?? '').normalize('NFKC')); }
  function ab2b64u(buf){
    const b = new Uint8Array(buf);
    let bin = '';
    const CHUNK = 0x8000;
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
  function showTip(el){ el.classList.add('show'); setTimeout(()=> el.classList.remove('show'), 1400); }

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

  // Envelope header builder/parsing (unchanged behaviour, robust bounds)
  function buildHeaderPBKDF2(params){
    const hash = (params.hash === 'SHA-512') ? 'SHA-512' : 'SHA-256';
    const iters = Math.min(Math.max(Number(params.iterations||600000), 120000), 1200000);
    return `x4v${X4V}|k=pbkdf2;i=${iters};h=${hash};alg=AES-GCM;layers=${LAYERS}||`;
  }
  function parseHeader(text){
    if (!text || typeof text !== 'string') return null;
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

  // Worker bootstrap: put the crypto code inside an inline worker (so we don't need a separate file)
  const workerCode = `
    // Worker scope
    const te = new TextEncoder(), td = new TextDecoder();

    function rand(n){ const a = new Uint8Array(n); self.crypto.getRandomValues(a); return a; }
    function concatBytes(a,b){
      const out = new Uint8Array((a?.length||0) + (b?.length||0));
      if (a) out.set(a,0);
      if (b) out.set(b, a ? a.length : 0);
      return out;
    }
    function str2bytes(s){ return te.encode((s ?? '').normalize('NFKC')); }

    function ab2b64u(buf){
      const b = new Uint8Array(buf);
      let bin = '';
      const CHUNK = 0x8000;
      for (let i=0;i<b.length;i+=CHUNK){ bin += String.fromCharCode.apply(null, b.subarray(i, i+CHUNK)); }
      return btoa(bin).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
    }
    function b64u2ab(b64u){
      let b64 = b64u.replace(/-/g,'+').replace(/_/g,'/'); while(b64.length % 4) b64 += '=';
      const bin = atob(b64); const out = new Uint8Array(bin.length);
      for (let i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
      return out.buffer;
    }

    function zeroBytes(u8){
      try{ if (u8 && typeof u8.fill === 'function') u8.fill(0); }catch(e){}
    }

    // PBKDF2 deriveKey -> AES-GCM key
    async function derivePBKDF2Bytes(passwordBytes, salt, ctx, iterations=600000, hash='SHA-256'){
      const pwdBuf = passwordBytes.slice(0); // copy
      try{
        const material = await crypto.subtle.importKey('raw', pwdBuf, 'PBKDF2', false, ['deriveKey']);
        const saltWithInfo = concatBytes(salt, str2bytes('|'+ctx));
        const key = await crypto.subtle.deriveKey(
          { name:'PBKDF2', salt: saltWithInfo, iterations, hash },
          material,
          { name:'AES-GCM', length:256 },
          false,
          ['encrypt','decrypt']
        );
        // Attempt to zero copy
        zeroBytes(new Uint8Array(pwdBuf));
        return key;
      } finally {
        // best-effort cleanup
      }
    }

    async function encLayer(dataInput, passwordBytes, params, ctx, aadBytes){
      const salt = rand(16), iv = rand(12);
      const key = await derivePBKDF2Bytes(passwordBytes, salt, ctx, params.iterations, params.hash);
      const plain = (dataInput instanceof ArrayBuffer || ArrayBuffer.isView(dataInput)) ? (dataInput.buffer || dataInput) : str2bytes(String(dataInput));
      const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv, additionalData: aadBytes, tagLength:128 }, key, plain);
      const out = new Uint8Array(salt.length + iv.length + ct.byteLength);
      out.set(salt,0); out.set(iv, salt.length); out.set(new Uint8Array(ct), salt.length+iv.length);
      return out.buffer;
    }

    async function decLayer(buf, passwordBytes, params, ctx, aadBytes){
      const bytes = new Uint8Array(buf);
      if (bytes.length < (16+12+16)) throw new Error('ciphertext too short');
      const salt = bytes.slice(0,16), iv = bytes.slice(16,28), ct = bytes.slice(28);
      const key = await derivePBKDF2Bytes(passwordBytes, salt, ctx, params.iterations, params.hash);
      return crypto.subtle.decrypt({ name:'AES-GCM', iv, additionalData: aadBytes, tagLength:128 }, key, ct);
    }

    async function quadEncrypt(plaintext, p1Str, p2Str, params, aadBytes){
      const p1Bytes = str2bytes(p1Str);
      const p2Bytes = str2bytes(p2Str);
      try{
        let l = await encLayer(plaintext, p1Bytes, params, 'layer1', aadBytes);
        l = await encLayer(l,        p1Bytes, params, 'layer2', aadBytes);
        l = await encLayer(l,        p2Bytes, params, 'layer3', aadBytes);
        l = await encLayer(l,        p2Bytes, params, 'layer4', aadBytes);
        return l;
      } finally {
        zeroBytes(p1Bytes); zeroBytes(p2Bytes);
        p1Str = ''; p2Str = '';
      }
    }

    async function quadDecrypt(b64u, p1Str, p2Str, params, aadBytes){
      const p1Bytes = str2bytes(p1Str);
      const p2Bytes = str2bytes(p2Str);
      try{
        let l = b64u2ab(b64u);
        l = await decLayer(l, p2Bytes, params, 'layer4', aadBytes);
        l = await decLayer(l, p2Bytes, params, 'layer3', aadBytes);
        l = await decLayer(l, p1Bytes, params, 'layer2', aadBytes);
        l = await decLayer(l, p1Bytes, params, 'layer1', aadBytes);
        return (typeof l === 'string') ? l : td.decode(new Uint8Array(l));
      } catch(e){
        return null;
      } finally {
        zeroBytes(p1Bytes); zeroBytes(p2Bytes);
        p1Str = ''; p2Str = '';
      }
    }

    async function calibratePBKDF2(targetMs=300, selectedHash='SHA-256'){
      const salt = rand(16);
      const mat = await crypto.subtle.importKey('raw', str2bytes('x4-cal'), 'PBKDF2', false, ['deriveBits']);
      let it = 150000; let dt = 0;
      while (it <= 1200000){
        const t0 = performance.now();
        await crypto.subtle.deriveBits({name:'PBKDF2', salt, iterations:it, hash:selectedHash}, mat, 256);
        dt = performance.now()-t0; if (dt >= targetMs*0.9) break;
        it = Math.floor(it*1.5);
      }
      return Math.min(Math.max(it, 120000), 1200000);
    }

    self.onmessage = async (ev) => {
      const msg = ev.data || {};
      try{
        if (msg.cmd === 'calibrate'){
          const it = await calibratePBKDF2(msg.targetMs || 300, msg.hash || 'SHA-256');
          self.postMessage({ id: msg.id, ok:true, result: it });
        } else if (msg.cmd === 'encrypt'){
          const buf = await quadEncrypt(msg.plaintext || '', msg.p1||'', msg.p2||'', msg.params||{iterations:600000,hash:'SHA-256'}, msg.aad);
          // Return base64url payload to avoid extra copying
          const b64 = ab2b64u(buf);
          // zero the ArrayBuffer
          try{ new Uint8Array(buf).fill(0); }catch(e){}
          self.postMessage({ id: msg.id, ok:true, result: b64 });
        } else if (msg.cmd === 'decrypt'){
          const out = await quadDecrypt(msg.payload || '', msg.p1||'', msg.p2||'', msg.params||{iterations:600000,hash:'SHA-256'}, msg.aad);
          if (out === null) self.postMessage({ id: msg.id, ok:false, err: 'decrypt-failed' });
          else self.postMessage({ id: msg.id, ok:true, result: out });
        } else {
          self.postMessage({ id: msg.id, ok:false, err:'unknown-cmd' });
        }
      } catch(e){
        // Do not leak exception text back to UI — just a generic error
        self.postMessage({ id: msg.id, ok:false, err:'internal-error' });
      }
    };
  `;

  // Create worker from blob
  let cryptoWorker = null;
  try{
    const blob = new Blob([workerCode], { type: 'application/javascript' });
    cryptoWorker = new Worker(URL.createObjectURL(blob));
  } catch (e) {
    cryptoWorker = null;
  }

  // Promise wrapper around worker postMessage
  let nextMsgId = 1;
  const pending = new Map();
  if (cryptoWorker){
    cryptoWorker.onmessage = (ev) => {
      const m = ev.data || {};
      const p = pending.get(m.id);
      if (p){
        pending.delete(m.id);
        if (m.ok) p.resolve(m.result);
        else p.reject(m.err || 'worker-error');
      }
    };
  }

  function workerCall(cmd, payload){
    return new Promise((resolve, reject) => {
      if (!cryptoWorker) return reject('no-worker');
      const id = nextMsgId++;
      pending.set(id, { resolve, reject });
      cryptoWorker.postMessage(Object.assign({ id, cmd }, payload));
      // timeout guard (e.g., if worker dies)
      setTimeout(()=> {
        if (pending.has(id)){
          pending.delete(id);
          reject('worker-timeout');
        }
      }, 120000); // 2 minutes
    });
  }

  // Fallback: if worker not available, refuse to proceed (better than doing PBKDF2 on main thread)
  function ensureCryptoAvailable(){
    if (!window.crypto?.subtle) throw new Error('WebCrypto not available');
    if (!cryptoWorker) throw new Error('Crypto worker not available; use a modern browser over HTTPS.');
  }

  // UI and behavior
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

  // init
  window.addEventListener('DOMContentLoaded', () => {
    showEnc();
    $('#tab-enc').addEventListener('click', showEnc);
    $('#tab-dec').addEventListener('click', showDec);

    $$('.eye').forEach(b=> b.addEventListener('click', ()=> {
      const id = b.getAttribute('data-for'); const i = document.getElementById(id);
      if (!i) return; i.type = (i.type==='password') ? 'text' : 'password';
    }));

    // Calibrate button — sends request to worker
    $('#pbkdf2-cal').addEventListener('click', async (ev)=>{
      const btn = ev.currentTarget;
      setBusy(btn, true);
      try{
        ensureCryptoAvailable();
        const selectedHash = $('#pbkdf2-hash').value === 'SHA-512' ? 'SHA-512' : 'SHA-256';
        const it = await workerCall('calibrate', { targetMs:300, hash: selectedHash });
        $('#pbkdf2-iters').value = String(it);
        validateOK($('#pbkdf2-iters'));
      }catch(e){
        invalidate($('#pbkdf2-iters'));
      }finally{ setBusy(btn, false); }
    });

    // Copy encrypted output
    $('#copy-enc').addEventListener('click', async ()=>{
      const v = $('#enc-out').value.trim(); if (!v) return;
      try{ await navigator.clipboard.writeText(v); showTip($('#tip-enc')); }catch(e){}
    });

    // Copy decrypted plaintext — require explicit confirmation
    $('#copy-dec').addEventListener('click', async ()=>{
      const v = $('#dec-out').value.trim(); if (!v) return;
      const ok = window.confirm('Copying plaintext to the clipboard is a risk. Proceed?');
      if (!ok) return;
      try{
        await navigator.clipboard.writeText(v);
        showTip($('#tip-dec'));
        // best-effort clear after 10s
        setTimeout(async ()=> {
          try{ await navigator.clipboard.writeText(''); }catch(e){}
        }, 10000);
      }catch(e){}
    });

    // Encrypt handler — offloads to worker
    $('#btn-enc').addEventListener('click', async (ev)=>{
      const btn = ev.currentTarget;
      const msgEl = $('#enc-msg'), p1El = $('#enc-p1'), p2El = $('#enc-p2'), out = $('#enc-out');
      [msgEl,p1El,p2El,out].forEach(x=> x.classList.remove('invalid','valid'));

      const msgVal = msgEl.value || '';
      const p1Val = p1El.value || '';
      const p2Val = p2El.value || '';

      if (!msgVal.trim()) { invalidate(msgEl); return; }
      if (!p1Val.trim()) { invalidate(p1El); return; }
      if (!p2Val.trim()) { invalidate(p2El); return; }
      if (msgVal.length > MAX_CHARS){ invalidate(msgEl); return; }

      const iterations = Math.min(Math.max(Number($('#pbkdf2-iters').value||600000),120000),1200000);
      const hashRaw = $('#pbkdf2-hash').value;
      const hash = (hashRaw === 'SHA-512') ? 'SHA-512' : 'SHA-256';

      const params = { iterations, hash };
      const header = buildHeaderPBKDF2(params);
      const aad = str2bytes(header);

      // clear password inputs in DOM immediately (reduce exposure)
      p1El.value = ''; p2El.value = '';

      setBusy(btn, true);
      try{
        ensureCryptoAvailable();
        const payloadB64u = await workerCall('encrypt', { plaintext: msgVal, p1: p1Val, p2: p2Val, params, aad });
        out.value = header + payloadB64u;
        validateOK(out);
      }catch(e){
        out.value = 'Encryption failed.'; invalidate(out);
      }finally{
        // clear references
        setBusy(btn, false);
      }
    });

    // Header detection UI
    function showDetected(text){
      const det = $('#kdf-detected');
      const parsed = parseHeader(text.trim());
      det.textContent = parsed ? `Detected: PBKDF2 (i=${parsed.params.iterations}, ${parsed.params.hash})` : '';
    }
    $('#dec-in').addEventListener('input', ()=> showDetected($('#dec-in').value));

    // Decrypt handler
    $('#btn-dec').addEventListener('click', async (ev)=>{
      const btn = ev.currentTarget;
      const txt = $('#dec-in'), p1El = $('#dec-p1'), p2El = $('#dec-p2'), out = $('#dec-out');
      [txt,p1El,p2El,out].forEach(x=> x.classList.remove('invalid','valid'));

      const inputVal = txt.value || '';
      const p1Val = p1El.value || '';
      const p2Val = p2El.value || '';

      if (!inputVal.trim()) { invalidate(txt); return; }
      if (!p1Val.trim()) { invalidate(p1El); return; }
      if (!p2Val.trim()) { invalidate(p2El); return; }

      // clear DOM password fields
      p1El.value = ''; p2El.value = '';

      setBusy(btn, true);
      try{
        ensureCryptoAvailable();

        let header, payload, params, aad;
        const parsed = parseHeader(inputVal);
        if (parsed && parsed.version === X4V){
          header = parsed.header + '||';
          payload = parsed.payload;
          params = parsed.params;
          aad = str2bytes(header);
        } else {
          // legacy: assume defaults, but create AAD from defaults
          payload = inputVal;
          params = { iterations:600000, hash:'SHA-256' };
          header = buildHeaderPBKDF2(params);
          aad = str2bytes(header);
        }

        const plain = await workerCall('decrypt', { payload, p1: p1Val, p2: p2Val, params, aad });
        if (!plain){
          out.value = 'Decryption failed. Check passwords and ensure ciphertext is intact.';
          invalidate(out);
        } else {
          out.value = plain;
          validateOK(out);
        }
      }catch(e){
        out.value = 'Decryption failed.'; invalidate(out);
      }finally{
        setBusy(btn, false);
      }
    });

    // Clear controls
    $('#btn-enc-clear').addEventListener('click', ()=>{ clearVal('enc-msg'); clearVal('enc-p1'); clearVal('enc-p2'); clearVal('enc-out'); });
    $('#btn-dec-clear').addEventListener('click', ()=>{ clearVal('dec-in'); clearVal('dec-p1'); clearVal('dec-p2'); clearVal('dec-out'); $('#kdf-detected').textContent=''; });

    if (!window.crypto?.subtle){
      alert('WebCrypto not available. Use a modern browser over HTTPS.');
    }
    if (!cryptoWorker){
      alert('High-cost crypto worker unavailable. Use a modern browser with Web Worker support for best performance and safety.');
    }
  });
})();
