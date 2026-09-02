# Identity chaining and ID-JAG, the receiving side (PROTOTYPE)

**Drafts:** `draft-ietf-oauth-identity-chaining-16`, `draft-ietf-oauth-identity-assertion-authz-grant-04`
**Feature flag:** `identity-chaining`, EXPERIMENTAL
**Acknowledgment version:** `draft-ietf-oauth-identity-chaining-16+draft-ietf-oauth-identity-assertion-authz-grant-04`
**Status:** prototype, and the **receiving** half only. This deployment accepts an identity assertion minted elsewhere. It does not yet request one.

## The problem it exists for

A person signs in to domain A. They then need to reach an API in domain B, and B does not trust A's access tokens -- nor should it, because an access token is a bearer credential minted for A's own resources with A's own lifetime and A's own revocation.

The alternatives are all worse:

| approach | what it costs |
|---|---|
| B trusts A's access tokens | B accepts a credential minted for someone else's resources, revoked on someone else's schedule |
| the user signs in again at B | a second identity for the same person, and a second thing to deprovision |
| a shared service account | the person disappears; every audit row in B says "the integration" |

Identity chaining splits it in two. A mints an **identity assertion** naming the user and the client that will present it; B accepts that assertion as an RFC 7523 authorization grant and mints its **own** token, under its **own** local identity, with its own lifetime and its own revocation. Neither domain trusts the other's tokens; B trusts A's *assertions about who signed in*, which is a far smaller thing.

## How it is built: layered ON the jwt-bearer grant, not beside it

An ID-JAG **is** an RFC 7523 assertion grant. So this is not a new door. It is four extra checks inside the door that already exists, and they run **after every control that touches the assertion**.

The order matters and is worth writing out, because one step is not where a reader would put it.

**First**, before the assertion is looked at: the **requested** scope passes the machine-grant floor and the presenting client's allowlist. This is deliberately early, so an out-of-policy request cannot spend the assertion's single-use `jti`. Note what it means for this prototype: when the client requests **no** scope -- the shape an ID-JAG flow normally takes -- this step validates **nothing**, because there is nothing to validate yet. That vacuity is exactly why the last step below exists.

**Then**, on the assertion itself:

1. the issuer is registered and enabled,
2. the signature verifies against that issuer's keys,
3. the audience is this deployment,
4. `sub` and `exp` are present and `exp` is in the future,
5. the `jti`, if present, has not been seen,
6. the subject has a **registered** mapping to a local principal (nothing is auto-provisioned),
7. the mapped principal passes its lifecycle fence.

**Then** the four ID-JAG checks. They add refusals and remove none, which is the whole reason for building it this way: a prototype that sat beside the grant would have had to re-implement all seven above, and the one it forgot would be the hole.

**Finally**, when the ID-JAG checks admitted a ceiling, that ceiling goes back through the same scope policy the first step used. See "The ceiling is not a second way in".

## The four checks

| check | without it |
|---|---|
| the header `typ` is `oauth-id-jag+jwt` | an issuer registered to federate a CI workload could present an assertion that speaks for a **person** |
| the presenting client is **confidential** | see below: the binding beneath it costs an interceptor nothing |
| `client_id` names the presenting client | the assertion is a bearer token for whoever intercepts it |
| `scope` is present, and bounds the issued **`scope`** | a **local** subject mapping could widen what the **authoritative** domain granted |

**The ceiling reaches `scope` and nothing else.** The minted token also carries `org_id` and `roles`, resolved from the **local** principal the assertion's subject maps to, and the assertion does not bound those. That follows from what this grant is -- B mints its own token under its own local identity -- but a resource server that authorizes on `roles` rather than on scope sees no ceiling at all. It is in the graduation list below.

### Why the presenting client must be confidential

This grant permits a **public** presenting client deliberately: the assertion is the authorization grant, so a workload trading one needs no client credential of its own. That is correct for a workload assertion and wrong for an identity assertion, and the difference is what the client binding is for.

For a public client, "authenticating as `cli_x`" is **typing `cli_x` into the form**. An interceptor reads the bound client id off the stolen assertion and sends it. The binding is satisfied for free, and the assertion is exactly the bearer token the binding exists to stop it being.

So an identity assertion requires a presenter that **proved** it is the named client. The ordinary jwt-bearer path is untouched: a public client still trades a plain bearer assertion, because there nothing claims to bind one.

The media type is compared with the optional and case-insensitive `application/` prefix, the same comparison the attestation prototype performs, for the same reason: `TokenTyp` names only profiles IronAuth mints and this one is a foreign party's.

An assertion carrying **no** `scope` is refused rather than treated as "everything the mapping allows". That default is the widening the last check exists to stop.

Each refusal records its **own** reason in the client-authentication diagnostics sink, while the wire answer stays the one uniform `invalid_grant` every assertion failure gives. An operator has to be able to separate an assertion minted for a **different** client, which is an interception, from an assertion carrying **no** `client_id` or no `scope`, which is an issuer that did not set the claim. Those are three different reasons and only the first is an attack. A caller must not be able to tell any of them apart.

## The assertion's scope is a ceiling, never a second way in

`scope` on the assertion says what the authoritative domain authorized. The presenting client's request, when it makes one, is intersected with it, and a request naming anything outside it is **refused** rather than quietly narrowed -- a client told it holds `admin` when it holds `read:orders` will act on the wrong belief.

When the client requests nothing, the assertion's scope becomes the granted scope, and **it is then validated exactly as a plainly requested scope is**: through the same function, against the same machine-grant floor and the same per-client allowlist, answering the same errors. That string was written by a foreign issuer, and without this an identity assertion would be a way to obtain scopes the very same client is refused when it asks plainly.

The one visible difference from a plainly requested scope is ordering. The ceiling is not known until the assertion is verified, so this check runs **after** the single-use `jti` is spent, and an out-of-policy assertion costs its `jti`. That is the right way round: the scope here is the foreign issuer's claim, not a string the caller varies per request, so the probing attack that the ordinary ordering prevents does not apply.

## With the flag off

An assertion carrying the ID-JAG media type is treated **exactly as it is on main today**: an ordinary bearer assertion from a trusted issuer. `typ` is not a separator the ordinary path reads, so none of the four checks apply and none of their refusals fire.

That is stated plainly because it is the sharp edge, not a footnote. It is also why the flag exists: the four checks are the entire difference between an identity assertion and a bearer one, and an operator has to opt into them.

## Turning it on

```toml
[features]
identity-chaining = { enabled = true, ack = "draft-ietf-oauth-identity-chaining-16+draft-ietf-oauth-identity-assertion-authz-grant-04" }
```

One flag, unlike the transaction-token prototype next door, which also needs a trust domain. But **it is not true that there is nothing to configure**, and the two things to set are the ones that bound what a foreign issuer can cause this deployment to mint:

1. **The presenting client must be confidential.** A public client cannot present an identity assertion at all, so the app that will do this needs a real `token_endpoint_auth_method`.
2. **Set that client's scope allowlist.** With no allowlist row a client may hold any scope outside the machine-grant floor, so an assertion authorizing `admin:all` mints a token carrying `admin:all`. That is not an escalation over what the client could already obtain by asking plainly, but it does move the choice of scope from your client to the remote issuer, and the allowlist is what takes it back.

The trust in the issuer itself is already expressed by the registered external issuer and the registered subject mapping this grant has always required.

The acknowledgment pins **both** drafts, so either one moving invalidates every acknowledgment in the wild and a routine upgrade refuses to boot for a deployment that enabled this. That is the flag working.

Nothing is mounted and nothing is advertised. The only visible sign that it is armed is a startup log line, which is why that line exists.

## Deviations from the drafts, stated

- **The receiving side only.** The requesting half -- this deployment exchanging its own token at a *foreign* authorization server to obtain an assertion -- is not built. A full chain needs both halves and this is one.
- **`jti` stays optional**, as RFC 7523 has it and as this grant has always had it. The ID-JAG draft leans on `jti` for single use; an assertion presented without one gets no replay protection here. Requiring it on identity assertions specifically would be a defensible tightening and is deliberately not done in a prototype, because it changes what a conformant issuer may send.
- **No `authorization_details`.** The draft carries RFC 9396 authorization details alongside `scope`; only `scope` is read.

## What a graduation still needs

- **Trust is per ISSUER, not per (issuer, trust domain).** This is the sharpest edge here. An external issuer registered for **workload** federation can, once the flag is on, present identity assertions that speak for people -- because the registration says "we trust this issuer" and nothing narrows that to a purpose. A graduation needs the registration to say which of the two an issuer may do.
- **The ceiling does not reach the local authorization claims.** `org_id` and `roles` are resolved from the mapped local principal, not from the assertion. Bounding them needs a decision this prototype does not make: whether a chained identity should carry the local principal's authority at all, or only what the authoritative domain named. A deployment whose resource servers authorize on `roles` should treat this prototype as bounding nothing they read.
- **No `sub_id`.** RFC 9493 structured subject identifiers are not read; the plain `sub` is matched against the registered mapping, which is what the ordinary grant has always done.
- **The requesting side.** See above.
- **No per-assertion audit distinction on the SUCCESS path.** A token minted from an identity assertion and one minted from an ordinary assertion produce the same audit shape, so an operator reading the log cannot tell which came through this path. The refusals are distinguished (each records its own diagnostic reason); the mints are not.
- **The flag is process-global, not per (tenant, environment).** Every other experimental surface here is resolved the same way, but it matters more for this one: arming it changes what an already-live grant accepts for every tenant this process serves, rather than mounting a route that only its own callers reach.
