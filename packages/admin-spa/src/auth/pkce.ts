// SPDX-License-Identifier: MIT OR Apache-2.0
//
// RFC 7636 PKCE for the console's public client login (issue #90, PR 2), built
// on WebCrypto. A public client cannot keep a secret, so PKCE is what binds the
// authorization code to the browser that requested it: the code_verifier is a
// high entropy random value, and only its S256 hash (the challenge) travels in
// the authorization redirect, so an intercepted code cannot be redeemed without
// the verifier. This module is pure browser crypto: it performs NO network call.

export interface Pkce {
  // The high entropy secret proven at the token endpoint.
  verifier: string;
  // The S256 (base64url SHA-256) challenge sent in the authorization request.
  challenge: string;
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// A URL safe random token with `byteLength` bytes of entropy.
function randomToken(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

// Build a fresh verifier and its S256 challenge.
export async function createPkce(): Promise<Pkce> {
  const verifier = randomToken(32);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return { verifier, challenge: base64UrlEncode(new Uint8Array(digest)) };
}

// A fresh opaque `state` value for CSRF protection on the authorization roundtrip.
export function randomState(): string {
  return randomToken(16);
}
