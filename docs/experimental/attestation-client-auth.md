# Attestation-based client authentication (PROTOTYPE)

**Draft:** `draft-ietf-oauth-attestation-based-client-auth-10`
**Feature flag:** `attestation-client-auth`, EXPERIMENTAL
**Acknowledgment version:** `draft-ietf-oauth-attestation-based-client-auth-10`
**Status:** prototype. Not advertised in discovery, not a supported method, and not covered by any compatibility promise.

## What it does

A client instance that holds no registered secret authenticates with two JWTs carried in headers:

| header | minted by | says |
|---|---|---|
| `OAuth-Client-Attestation` | an ATTESTER the deployment trusts | "the party holding this key is an instance of this `client_id`" |
| `OAuth-Client-Attestation-PoP` | the client instance | "I hold that key" |

Neither alone authenticates anything. The authorization server learns which client it is talking to from the attester it already trusts, never from the instance: an instance that could name its own `client_id` could impersonate any client whose attester it could reach.

The method is accepted on the **client-credentials grant** only, and only for a client whose registered `token_endpoint_auth_method` is `attest_jwt_client_auth`.

## Turning it on

Two conditions, and neither implies the other.

```toml
[features]
attestation-client-auth = { enabled = true, ack = "draft-ietf-oauth-attestation-based-client-auth-10" }

[[oidc.attestation_client_auth.attesters]]
issuer = "https://attester.example.com"
jwks = '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"...","kid":"..."}]}'
```

The flag says the operator accepts a draft-stage wire format. The list says whose attestations they believe. **With the flag on and no attester configured, the method authenticates nobody** and a warning says so at boot: there is no wildcard and no "any valid signature" mode, because the attester is the party that decides which `client_id` an instance may claim.

## The upgrade risk, stated plainly

**The acknowledgment version is the draft revision itself**, not a `0.1.0-exp.N` counter. That is deliberate: what an operator acknowledges here is a wire format the IETF may still change, so a draft bump invalidates every acknowledgment in the wild. That is the correct behaviour, and it means **a routine IronAuth upgrade can refuse to boot** for a deployment that enabled this. Read that as the flag working, not failing.

**A deliberate deviation.** The draft makes `aud` OPTIONAL on the client attestation JWT; it is REQUIRED on the PoP. IronAuth requires it on both, because the JOSE verification policy has no optional-audience mode by construction: a policy that does not name an expected audience does not compile, and that is a property worth keeping. The security effect is additive; the **interop** effect is real, and an attester that follows the draft literally and omits `aud` is refused here. Closing this at graduation means either an optional-audience mode in the JOSE seam or a documented profile requirement on the attester.

## What a graduation still needs

Stated so nothing here reads as finished.

- **Replay recording.** The PoP's `jti` is required and returned, and this build does not record it. A replayed proof inside its own lifetime is accepted. The store seam `private_key_jwt` uses for exactly this exists and is where the wiring goes. Until it is wired, the only bound on the reuse window is a **five-minute maximum PoP lifetime**, enforced rather than documented.
- **Attester key rotation.** Trust is a static, inline key set. A rotating attester is a config change. A JWKS-fetching registry means a fetch, a cache, a rotation policy and an SSRF surface, all of which are graduation work.
- **The attestation's optional claims.** `aal`, `key_type`, `user_authentication` and `status` carry assurance level and revocation, and are not read. A deployment making authorization decisions on them would need them enforced.
- **Grants beyond client credentials.** An attested instance asking for its own token is the shape the draft targets; the other grants are unchanged.

## What it refuses, and why each refusal is an attack

Every one has a test in `crates/ironauth-oidc/tests/attestation_client_auth.rs`, driven by minting the attack with exactly one thing changed from an honest pair.

- **A PoP signed by a key the attestation did not bind.** Otherwise an attacker replays somebody else's attestation with their own key and becomes that client. The proof is verified against the bound key and nothing else: that trusted set has exactly one member.
- **An attestation whose `sub` is not the authenticating client.** Otherwise an attestation for client A authenticates client B.
- **An attestation from an unregistered issuer.** The issuer is read unverified only to SELECT a key set, exactly as a `kid` is; it can narrow the trusted set, never extend it.
- **The two JWTs swapped**, and an attestation wearing the proof's media type. They share an issuer relationship and a key chain, and `typ` is what tells them apart (RFC 8725 section 3.11).
- **A PoP minted for another deployment.** `aud` is matched exactly, so a proof harvested at one deployment is inert at another that trusts the same attester.
- **A PoP with no `jti`**, so replay recording has something to record when it is wired.
- **Anything expired**, and any PoP claiming a lifetime longer than five minutes.
