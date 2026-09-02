# Transaction tokens (PROTOTYPE)

**Draft:** `draft-ietf-oauth-transaction-tokens-09`
**Feature flag:** `transaction-tokens`, EXPERIMENTAL
**Acknowledgment version:** `draft-ietf-oauth-transaction-tokens-09`
**Status:** prototype. Requested through RFC 8693 token exchange; refused as an unsupported token type unless armed.

## The problem it exists for

A request enters a trust domain at the edge, authenticated as a person. It then fans out across a dozen internal services, and each hop needs three things the original access token cannot carry together: **which person**, **which workload is asking now**, and **what the original request was authorized to do**.

The usual answers are all bad:

| approach | what it loses |
|---|---|
| pass the user's access token inward | every service becomes a confused deputy holding a credential good at the edge |
| mint service-to-service tokens | the person |
| pass an unsigned header | everything, the moment one hop is compromised |

A transaction token is a short-lived signed JWT scoped to **one transaction inside one trust domain**, carrying all three.

## What it mints

`typ: txn_token` (the draft's media type; it carries no `+jwt` suffix, which is the draft's choice), with:

| claim | from | why |
|---|---|---|
| `iss` | this environment's issuer | who signed it |
| `aud` | the configured trust domain | where it may be spent, and nowhere else |
| `sub` | the **revalidated** subject token | which person the request is for |
| `txn` | a fresh id | the transaction every hop shares |
| `rctx` | the authenticated client | which workload asked for this token (see the deviation below) |
| `azd` | the exchange's **decided** scope | what *this* request was authorized to do |
| `act` | the exchange's decision, for a **delegation** | who is acting for the subject |
| `purp` | **not set** | see below |
| `iat`, `exp` | the clock | at most five minutes |

`sub` comes from a token the exchange **verified in full**, never from a claim read out of an unverified payload. That is the token-exchange module's central invariant, and this composes on it rather than beside it.

## The audience is the whole security story

A transaction token is intra-domain **by construction**: it names the trust domain as its audience, and a service outside that domain has no reason to accept it. That is the only thing standing between "a short-lived internal assertion" and "a bearer credential that escaped".

So the audience is operator-configured and **required**. With none set, the token type is refused rather than minted against a default, because **a default trust domain is a trust domain nobody chose.**

## Turning it on

```toml
[features]
transaction-tokens = { enabled = true, ack = "draft-ietf-oauth-transaction-tokens-09" }

[oidc]
transaction_token_trust_domain = "internal.example.com"
```

Two conditions, neither implying the other. The flag says the operator accepts a draft-stage wire format; the domain says where these tokens may be spent. **With either missing, the requested token type is refused exactly as any unknown URI is** -- so a deployment that has not opted in cannot tell from the answer that the type means anything here.

Then, on the token endpoint:

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<the user's access token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
requested_token_type=urn:ietf:params:oauth:token-type:txn_token
```

**An absent `act` is ambiguous, deliberately.** It means a downscope **or** an impersonation: RFC 8693 §1.1 defines impersonation as the actor not being distinguishable in the token. A service in the trust domain cannot tell the two apart and is not meant to -- the audit row's `mode=` is where that distinction lives, which is why the row records it. An impersonated transaction token is traceable only through that row.

**`audience` and `resource` are refused, not ignored.** A transaction token's audience is the trust domain, so a request that also names a target asked for two different things. It answers `invalid_target`, which is what the ordinary exchange answers for an unregistered one -- silently ignoring a narrowing request would leave the caller believing it constrained something it did not.

**`purp` is not set.** The draft defines the claim and defines no request parameter that carries it, and the only free string a caller can send on this endpoint is `scope`, which means *narrow to this* everywhere else here. Reading it as a purpose would make one parameter mean two things depending on the requested token type. A graduation that wants `purp` should define a parameter for it.

**The acknowledgment version is the draft revision itself.** A draft bump invalidates every acknowledgment in the wild, so a routine IronAuth upgrade can refuse to boot for a deployment that enabled this. That is the flag working.

## Deviations from the draft, stated

- **`act` rides in the token for a delegation** and is deliberately absent for an impersonation, per RFC 8693 §1.1. Delegation is the only exchange mode with no per-client policy flag, so `act` is its whole accountability control.
- **`rctx` is `{"workload": "<client id>"}`**, which is IronAuth's shape, not one the draft prescribes. The draft leaves the requester context's contents to the deployment; this is the smallest thing that answers "which workload asked".
- **`azd` is `{"scope": [...]}`** carrying the exchange's decided scope, where the draft's `azd` is a rich object describing what was authorized.
- **`purp` is never set** (see above).

## What a graduation still needs

- **`azd` is the exchange's decided scope, not RFC 9396 authorization details.** The draft's `azd` is a rich object describing what was authorized; this carries the narrowed scope this exchange settled on -- what *this* request may do, not everything the subject token held. A deployment making decisions on `azd` would need the richer shape, and the edge would have to carry it in.
- **No replacement flow, so `txn` is not shared across a call chain.** The draft's model is that the first hop mints and later hops request a **replacement** carrying the same `txn`. Here every request mints a fresh id, so two hops of one logical transaction get two ids and nothing correlates them.
- **No `sub_id`.** The draft allows a structured subject identifier (RFC 9493); this carries the plain `sub` the subject token carried.
- **One trust domain per PROCESS, shared by every tenant.** The domain is a single config field read once at boot, while the issuer is per (tenant, environment), so every tenant this process serves mints with the same `aud`. For a multi-tenant deployment that is the wrong axis and it is the first thing a graduation has to change.
- **No replay recording and no revocation.** A transaction token is bearer and unrevocable for its lifetime; the five-minute cap is the whole mitigation, which is why it is clamped at the mint rather than configured.
