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

  // Zeroing helper
  function zeroBytes(u8){
    try{ if (u8 && typeof u8.fill === 'function') u8.fill(0); }catch(e){}
  }

  // Envelope header (AAD-bound)
  const X4V = 2, LAYERS = 4;
  function buildHeaderPBKDF2(params){
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

  // PBKDF2 (password bytes -> CryptoKey)
  // passwordBytes: Uint8Array
  async function derivePBKDF2Bytes(passwordBytes, salt, ctx, iterations=600000, hash='SHA-256'){
    // make a compact copy of password bytes and import that ArrayBuffer (avoid referencing original large buffer)
    const pwdBuf = passwordBytes.buffer.slice(passwordBytes.byteOffset, passwordBytes.byteOffset + passwordBytes.byteLength);
    try{
      const material = await crypto.subtle.importKey('raw', pwdBuf, 'PBKDF2', false, ['deriveKey']);
      // Domain separation: salt || '|' || ctx
      const saltWithInfo = concatBytes(salt, str2bytes('|'+ctx));
      const key = await crypto.subtle.deriveKey(
        { name:'PBKDF2', salt: saltWithInfo, iterations, hash },
        material,
        { name:'AES-GCM', length:256 },
        false,
        ['encrypt','decrypt']
      );
      // Attempt to zero the copied pwdBuf
      try{ const tmp = new Uint8Array(pwdBuf); tmp.fill(0); }catch(e){}
      return key;
    } finally {
      // best-effort: caller should zero their passwordBytes after this call
    }
  }

  // AES-GCM layer ops (AAD-bound with header)
  async function encLayer(dataInput, passwordBytes, params, ctx, aadBytes){
    const salt = rand(16), iv = rand(12);
    const key = await derivePBKDF2Bytes(passwordBytes, salt, ctx, params.iterations, params.hash);
    const plain = (dataInput instanceof ArrayBuffer || ArrayBuffer.isView(dataInput)) ? (dataInput.buffer || dataInput) : str2bytes(String(dataInput));
    const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv, additionalData: aadBytes }, key, plain);
    const out = new Uint8Array(salt.length + iv.length + ct.byteLength);
    out.set(salt,0); out.set(iv, salt.length); out.set(new Uint8Array(ct), salt.length+iv.length);
    // Do not try to return CryptoKey or other sensitive objects
    return out.buffer;
  }
  async function decLayer(buf, passwordBytes, params, ctx, aadBytes){
    const bytes = new Uint8Array(buf);
    const salt = bytes.slice(0,16), iv = bytes.slice(16,28), ct = bytes.slice(28);
    const key = await derivePBKDF2Bytes(passwordBytes, salt, ctx, params.iterations, params.hash);
    return crypto.subtle.decrypt({ name:'AES-GCM', iv, additionalData: aadBytes }, key, ct);
  }

  // Quad-layer: convert passwords to bytes early, clear DOM inputs ASAP, zero buffers after use
  async function quadEncrypt(plaintext, p1Str, p2Str, params, aadBytes){
    // convert immediately to bytes and clear inputs
    const p1Bytes = str2bytes(p1Str);
    const p2Bytes = str2bytes(p2Str);
    // zero out plaintext DOM in caller; here we operate on the passed plaintext
    try{
      let l = await encLayer(plaintext, p1Bytes, params, 'layer1', aadBytes);
      l = await encLayer(l,        p1Bytes, params, 'layer2', aadBytes);
      l = await encLayer(l,        p2Bytes, params, 'layer3', aadBytes);
      l = await encLayer(l,        p2Bytes, params, 'layer4', aadBytes);
      return l;
    } finally {
      // zero password bytes as soon as possible
      zeroBytes(p1Bytes); zeroBytes(p2Bytes);
      // attempt to obliterate string refs (caller should also clear DOM)
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
      return bytes2str(l);
    } catch(e){
      // Generic failure (do not leak stack or internals)
      return null;
    } finally {
      zeroBytes(p1Bytes); zeroBytes(p2Bytes);
      p1Str = ''; p2Str = '';
    }
  }

  // Calibrate PBKDF2 (~300ms target). Use selected hash algorithm.
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
        const selectedHash = $('#pbkdf2-hash').value === 'SHA-512' ? 'SHA-512' : 'SHA-256';
        const it = await calibratePBKDF2(300, selectedHash);
        $('#pbkdf2-iters').value = it;
        validateOK($('#pbkdf2-iters'));
      }catch(e){
        invalidate($('#pbkdf2-iters'));
      }finally{ setBusy(btn, false); }
    });

    // Copy buttons
    $('#copy-enc').addEventListener('click', async ()=>{
      const v = $('#enc-out').value.trim(); if (!v) return;
      try{ await navigator.clipboard.writeText(v); showTip($('#tip-enc')); }catch(e){}
    });

    // For plaintext copying, ask explicit confirmation and attempt clipboard clear after a delay
    $('#copy-dec').addEventListener('click', async ()=>{
      const v = $('#dec-out').value.trim(); if (!v) return;
      // require explicit user confirmation to put plaintext into clipboard
      const ok = window.confirm('Copying plaintext to the clipboard is a risk. Proceed?');
      if (!ok) return;
      try{
        await navigator.clipboard.writeText(v);
        showTip($('#tip-dec'));
        // attempt to clear clipboard after 10 seconds (best-effort)
        setTimeout(async ()=> {
          try{ await navigator.clipboard.writeText(''); }catch(e){}
        }, 10000);
      }catch(e){}
    });

    // Encrypt
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

      // Immediately clear password inputs in DOM to reduce time they exist as strings in the document
      p1El.value = ''; p2El.value = '';
      // Keep local copies of password strings just long enough to convert to bytes below
      setBusy(btn, true);
      try{
        const buf = await quadEncrypt(msgVal, p1Val, p2Val, params, aad);
        out.value = header + ab2b64u(buf);
        validateOK(out); // green on success
        // Optionally clear the message input after encrypt to reduce plaintext lingering
        // Note: keep message visible for user unless they choose to clear
      }catch(e){
        out.value = 'Encryption failed.'; invalidate(out);
      }finally{
        // zero local string refs
        // (strings cannot be zeroed but we remove references)
        // p1Val/p2Val go out of scope; encourage GC
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
      const txt = $('#dec-in'), p1El = $('#dec-p1'), p2El = $('#dec-p2'), out = $('#dec-out');
      [txt,p1El,p2El,out].forEach(x=> x.classList.remove('invalid','valid'));

      const inputVal = txt.value || '';
      const p1Val = p1El.value || '';
      const p2Val = p2El.value || '';

      if (!inputVal.trim()) { invalidate(txt); return; }
      if (!p1Val.trim()) { invalidate(p1El); return; }
      if (!p2Val.trim()) { invalidate(p2El); return; }

      // Clear password inputs in DOM immediately to reduce exposure
      p1El.value = ''; p2El.value = '';

      setBusy(btn, true);
      try{
        let header, payload, params, aad;

        const parsed = parseHeader(inputVal);
        if (parsed && parsed.version === X4V){
          header = parsed.header + '||';
          payload = parsed.payload;
          params = parsed.params;
          aad = str2bytes(header);
        } else {
          // Legacy (no header): assume PBKDF2 defaults and build AAD from them
          payload = inputVal;
          params = { iterations:600000, hash:'SHA-256' };
          header = buildHeaderPBKDF2(params);
          aad = str2bytes(header);
        }

        const plain = await quadDecrypt(payload, p1Val, p2Val, params, aad);
        if (plain === null){
          out.value = 'Decryption failed. Check passwords and ensure header/ciphertext is intact.';
          invalidate(out); // red on failure
        } else {
          out.value = plain;
          validateOK(out); // green on success
        }
      }catch(e){
        out.value='Decryption failed.'; invalidate(out);
      }finally{
        // encourage GC of password strings
        setBusy(btn, false);
      }
    });

    // Clear
    $('#btn-enc-clear').addEventListener('click', ()=>{ clearVal('enc-msg'); clearVal('enc-p1'); clearVal('enc-p2'); clearVal('enc-out'); });
    $('#btn-dec-clear').addEventListener('click', ()=>{ clearVal('dec-in'); clearVal('dec-p1'); clearVal('dec-p2'); clearVal('dec-out'); $('#kdf-detected').textContent=''; });

    if (!window.crypto?.subtle){ alert('WebCrypto not available. Use a modern browser over HTTPS.'); }
  });
})();
