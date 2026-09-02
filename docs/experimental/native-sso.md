# Native SSO for mobile apps (PROTOTYPE)

**Specification:** OpenID Connect Native SSO for Mobile Apps 1.0, Implementer's Draft 2
**Feature flag:** `native-sso`, EXPERIMENTAL
**Acknowledgment version:** `openid-connect-native-sso-1_0-ID2`
**Status:** prototype. Off by default; with it off, no ID token carries `ds_hash` and the token exchange refuses an ID-token subject exactly as it does today.

## The problem it exists for

A vendor ships three apps on one phone. The person signs in to the first, opens the second, and is asked to sign in again.

That is not a bug in the apps. On mobile there is no shared browser session to ride: each app gets its own `ASWebAuthenticationSession` or Custom Tab, and both platforms have spent a decade making sure one app cannot read another's cookies. The web answer does not exist here, and should not.

Native SSO gives the family a **shared secret** instead of a shared cookie.

## How it works

1. App A completes an ordinary code flow and asks for the `device_sso` scope.
2. The token response carries a **`device_secret`** beside the usual tokens, and app A's ID token carries **`ds_hash`**, the hash of that secret.
3. App B presents **app A's ID token together with the device secret** through RFC 8693 token exchange, and receives its **own** tokens for the same person.

App B never sees app A's access or refresh token, and the person signs in once.

## Why the ID token alone is not enough

An ID token is an authentication **receipt**. It says a person signed in; it is not a credential. It is audienced to one client, it is frequently logged, and this deployment's token exchange **refuses one as a `subject_token`** for exactly that reason : `check_request_shape` says so in as many words, because an ID token that could be traded is a confused deputy.

`ds_hash` is what changes that, and only for the pair:

| presented alone | what it gets you |
|---|---|
| a stolen ID token | nothing: the exchange needs the secret whose hash it carries |
| a stolen device secret | nothing: the exchange needs the ID token bound to that secret |
| both | the sibling app's tokens, which is the feature |

So the relaxation of the subject-type rule is **joint**. A request naming the ID-token subject type *without* the device-secret actor type is not a partially formed Native SSO exchange; it is precisely the request the ordinary rule exists to refuse, and it is refused.

## The order of checks is the security argument

The device secret is redeemed **first**, and everything after it is checked against the row redemption returned rather than against the presented token:

1. the secret's SHA-256 finds a **live, unrevoked, unexpired** row, or there is nothing here;
2. the ID token is verified against the audience **that row names** : signature, this issuer, the ID-token media type, and unexpired;
3. `ds_hash` in the verified token must be the hash of the secret actually presented;
4. the token's subject must be the person the row is for.

Reading `aud` out of the presented token to decide which audience to verify it against would be a check the caller controls both sides of. It is not done.

## Revoking severs the SSO set

Signing a person out ends the family's ability to bootstrap. The device-secret row hangs off the **sign-in**, not off the app that asked for it, so logging out revokes every live secret from that session in the same operation that revokes the session and its refresh families.

That distinction is load-bearing and is the one thing a reader should take from the schema. The ID token's `sid` is **per-client** by design, so that one relying party cannot correlate a person across another's tokens. Keying the device secret on `sid` would have severed only the app that happened to ask and left its siblings minting: the criterion failing silently, with the revocation appearing to succeed.

## Turning it on

```toml
[features]
native-sso = { enabled = true, ack = "openid-connect-native-sso-1_0-ID2" }
```

Then a client asks for `device_sso` in its authorization request. Nothing else is configured: the secret's lifetime is clamped at the mint rather than exposed, for the reason below.

## Deviations and limits, stated

- **The device secret is a BEARER credential.** The draft's DPoP-binding question is open and this prototype does not answer it. Anything that reads the secret out of the device can use it from anywhere, until it expires or the session ends. This is the sharpest edge here.
- **Nothing binds it to the device** beyond the name. There is no attestation, no key, no platform binding.
- **The lifetime is clamped at 30 days at the mint, not configured.** A credential for a whole app family that an operator could set to a year is a year-long key to every sibling's tokens, and the apps holding it cannot revoke it themselves.
- **Returned once.** Only the SHA-256 digest is stored, so an app that loses the secret must sign in again, which is the correct outcome for a credential that speaks for a family.
- **No `device_secret` rotation.** The draft allows the exchange to return a fresh secret; this returns none, so the family's secret is the one it got at sign-in until the session ends.

## What a graduation still needs

- **The DPoP binding**, or a stated decision not to. Every other limit here is smaller than this one.
- **Device binding**, so an exfiltrated secret does not work from another machine.
- **Rotation on redemption**, which bounds the damage of a leaked secret to one exchange rather than to the session's lifetime.
- **An operator surface.** The SSO set is severable, but nothing lists it: an operator cannot see which secrets are live for a person without reading the table.
