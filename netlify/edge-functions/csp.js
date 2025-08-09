// netlify/edge-functions/csp.js
// Runs at the edge on every request (Deno runtime)

export default async (request, context) => {
  // 1) Generate a base64 nonce
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const nonce = btoa(String.fromCharCode(...bytes)); // e.g. "p8K0...=="

  // 2) Fetch the original response from your static files
  const res = await context.next();

  // Only process HTML responses
  const ct = res.headers.get('content-type') || '';
  if (!ct.includes('text/html')) {
    // Still attach global security headers to non-HTML if you want:
    const passHeaders = new Headers(res.headers);
    hardenHeaders(passHeaders); // optional helper below
    return new Response(res.body, { status: res.status, headers: passHeaders });
  }

  // 3) Read and patch HTML: replace all "X4-NONCE" placeholders
  const html = await res.text();
  const patched = html.replaceAll('X4-NONCE', nonce);

  // 4) Set CSP and other security headers
  const headers = new Headers(res.headers);
  // Strong CSP: only allow inline scripts/styles with this nonce
  headers.set(
    'Content-Security-Policy',
    [
      "default-src 'none'",
      `script-src 'self' 'nonce-${nonce}'`,
      `style-src 'self' 'nonce-${nonce}'`,
      "img-src 'self' data:",
      "connect-src 'none'",
      "font-src 'none'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "base-uri 'none'",
      "form-action 'none'",
      "block-all-mixed-content",
      "require-trusted-types-for 'script'",
      "trusted-types x4",
    ].join('; ')
  );

  // Optional extra hardening headers
  hardenHeaders(headers);

  // Ensure correct content-type for HTML
  headers.set('content-type', 'text/html; charset=utf-8');

  // 5) Return patched HTML with headers
  return new Response(patched, { status: res.status, headers });
};

// Optional: shared hardening headers
function hardenHeaders(h) {
  h.set('Referrer-Policy', 'no-referrer');
  h.set('X-Content-Type-Options', 'nosniff');
  h.set('Permissions-Policy', "camera=(), microphone=(), geolocation=()");
  h.set('Cross-Origin-Opener-Policy', 'same-origin');
  // COEP is safe if you don't embed cross-origin assets:
  // h.set('Cross-Origin-Embedder-Policy', 'require-corp');
  // Avoid caching HTML so each response carries a fresh nonce:
  // If you want caching, tune carefully with ETag/Vary; simplest is no-store.
  h.set('Cache-Control', 'no-store');
}
