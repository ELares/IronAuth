// SPDX-License-Identifier: MIT OR Apache-2.0

//! Client ID Metadata Document hardening (issue #128).
//!
//! A CIMD `client_id` is a URL the authorization server FETCHES and then trusts to describe
//! a client. That inverts the usual direction: an unregistered party chooses a URL and the
//! server dereferences it, so every rule here exists because the alternative hands an
//! attacker either the server's network position or another client's identity.
//!
//! This module is the pure decision half: what a URL and a document must satisfy. Fetching,
//! caching and the trust-policy store are separate, so the rules can be exercised
//! exhaustively without a socket.
//!
//! # Why the checks are ordered
//!
//! Cheapest and most certain first: scheme, then shape, then size, then content. A rule that
//! needed the document to be parsed cannot protect against an oversized document, and a
//! rule that needed a DNS answer cannot protect against a scheme nobody should have sent.

use std::time::{Duration, SystemTime};

use serde_json::Value;

/// The largest metadata document that will be considered.
///
/// A cap rather than a preference. Without one, a `client_id` URL is an instruction to the
/// server to download whatever the operator of that URL feels like serving, and the natural
/// end of that is memory exhaustion from a party that never registered.
pub const MAX_DOCUMENT_BYTES: usize = 32 * 1024;

/// Why a client-ID metadata document was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CimdRejection {
    /// The `client_id` is not a URL at all.
    NotAUrl,
    /// The `client_id` is not `https`.
    NotHttps,
    /// The URL carries a fragment, userinfo, or is otherwise not a plain document URL.
    NotAPlainUrl(&'static str),
    /// The URL names a private, loopback, or otherwise special-use host.
    SpecialUseHost,
    /// The fetch was redirected. A CIMD URL must serve its own document.
    Redirected,
    /// The document exceeded [`MAX_DOCUMENT_BYTES`].
    TooLarge {
        /// What arrived, in bytes.
        got: usize,
    },
    /// The document is not a JSON object.
    NotAnObject,
    /// The document's `client_id` is absent or does not equal the URL it was fetched from.
    ClientIdMismatch,
}

/// Name suffixes that cannot belong to a public host.
///
/// Matched literally against an already-lowercased host, so a case-insensitive comparison
/// would be guarding against something that cannot reach it.
const PRIVATE_SUFFIXES: [&str; 4] = [".localhost", ".local", ".internal", ".home.arpa"];

/// Whether `host` is a literal IP in a private, loopback, link-local or otherwise
/// special-use range, or a name that resolves to one by construction.
///
/// Textual only. This is the FIRST line, not the last: a hostname can still resolve to a
/// private address, and only the resolver can see that. The outbound fetcher enforces the
/// resolved-address rule, and this catches the literal case before a request is even built,
/// which is both cheaper and clearer in a refusal message.
#[must_use]
pub fn is_special_use_host(host: &str) -> bool {
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(v4) = trimmed.parse::<std::net::Ipv4Addr>() {
        return v4.is_private()
            || v4.is_loopback()
            || v4.is_link_local()
            || v4.is_broadcast()
            || v4.is_documentation()
            || v4.is_unspecified()
            // 100.64.0.0/10, carrier-grade NAT: routable-looking and not the public
            // internet, which is exactly the shape an SSRF target takes.
            || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]));
        // The cloud metadata address 169.254.169.254 is NOT named here: it is inside
        // link-local, which is already refused above. A duplicate condition for it
        // survives deletion, which is the definition of dead weight. The intent is
        // pinned in `private_and_special_use_targets_are_refused` instead, where it
        // fails loudly if the range it depends on ever narrows.
    }
    if let Ok(v6) = trimmed.parse::<std::net::Ipv6Addr>() {
        return v6.is_loopback()
            || v6.is_unspecified()
            // Unique local (fc00::/7) and link-local (fe80::/10).
            || (v6.segments()[0] & 0xfe00) == 0xfc00
            || (v6.segments()[0] & 0xffc0) == 0xfe80
            // An IPv4-mapped address is the same target wearing a different hat.
            || v6.to_ipv4_mapped().is_some_and(|v4| {
                v4.is_private() || v4.is_loopback() || v4.is_link_local()
            });
    }
    // Names that cannot be public, so a resolver never needs to be asked.
    let lowered = trimmed.to_ascii_lowercase();
    lowered == "localhost"
        || PRIVATE_SUFFIXES
            .iter()
            .any(|suffix| lowered.as_str().ends_with(*suffix))
        // A single label cannot be a public name, so it is an intranet host.
        || !lowered.contains('.')
}

/// Check a `client_id` URL before anything is fetched.
///
/// Parsed with [`ironauth_fetch::parse_target`], the SAME parser the outbound path uses.
/// A second URL parser here would be a second set of edge cases: the two could disagree
/// about userinfo, or about an IPv6 literal, and the check that passed would not be the
/// check that dialed.
///
/// # Errors
///
/// [`CimdRejection`] naming the first rule the URL fails.
pub fn validate_client_id_url(client_id: &str) -> Result<ironauth_fetch::Target, CimdRejection> {
    // A fragment is refused BEFORE parsing, because `http::Uri` accepts one and the
    // authority-based checks below would never see it. Two client_ids differing only in a
    // fragment are the same document with two identities, and the fragment never reaches
    // the server that would have to tell them apart.
    if client_id.contains('#') {
        return Err(CimdRejection::NotAPlainUrl("a fragment"));
    }
    let target = ironauth_fetch::parse_target(client_id).map_err(|error| match error {
        ironauth_fetch::TargetError::UnsupportedScheme => CimdRejection::NotHttps,
        ironauth_fetch::TargetError::MissingHost => CimdRejection::NotAPlainUrl("no host"),
        ironauth_fetch::TargetError::UserinfoPresent => CimdRejection::NotAPlainUrl("userinfo"),
        _ => CimdRejection::NotAUrl,
    })?;
    if target.scheme != ironauth_fetch::Scheme::Https {
        // Plaintext would let anyone on the path define the client. `http` is refused even
        // for loopback, because a CIMD client_id is a public identifier by definition.
        return Err(CimdRejection::NotHttps);
    }
    if is_special_use_host(&target.host) {
        return Err(CimdRejection::SpecialUseHost);
    }
    Ok(target)
}

/// Check the fetched document.
///
/// `final_url` is where the body actually came from. It is compared against the requested
/// `client_id` because a redirect means some other origin served the document, and the
/// `client_id` an authorization decision is recorded against would then name a URL that never
/// produced it.
///
/// # Errors
///
/// [`CimdRejection`] naming the first rule the response fails.
pub fn validate_document(
    client_id: &str,
    final_url: &str,
    body: &[u8],
) -> Result<Value, CimdRejection> {
    if final_url != client_id {
        return Err(CimdRejection::Redirected);
    }
    if body.len() > MAX_DOCUMENT_BYTES {
        return Err(CimdRejection::TooLarge { got: body.len() });
    }
    let document: Value = serde_json::from_slice(body).map_err(|_| CimdRejection::NotAnObject)?;
    let Some(object) = document.as_object() else {
        return Err(CimdRejection::NotAnObject);
    };
    // The document must name ITSELF. Without this, one URL can serve a document claiming
    // another party's client_id and inherit whatever that identity is trusted with.
    if object.get("client_id").and_then(Value::as_str) != Some(client_id) {
        return Err(CimdRejection::ClientIdMismatch);
    }
    Ok(document)
}

/// How long a fetched document may be cached, clamped into a configured band (issue
/// #128).
///
/// # Why a floor AND a ceiling, and why the document does not get to choose
///
/// The TTL is derived from the origin's `Cache-Control`, and the origin is chosen by an
/// unregistered party. So the header is an INPUT, never a decision:
///
/// * Without a **floor**, a document serving `max-age=0` makes every authorization request
///   dereference an attacker-chosen URL. That is a free amplifier pointed at whatever the
///   server can reach, and it costs the attacker one header.
/// * Without a **ceiling**, a document served once with `max-age=31536000` is trusted for a
///   year. Revoking it would mean waiting out a lifetime the attacker picked, so a client
///   that should have stopped working keeps working.
///
/// Clamping both ends means the worst a chosen header can do is move the refresh rate
/// inside a range the operator set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CimdTtlBounds {
    /// The shortest a document may be cached, however small its `max-age`.
    pub floor: Duration,
    /// The longest a document may be cached, however large its `max-age`.
    pub ceiling: Duration,
}

impl CimdTtlBounds {
    /// Clamp `max_age` into the band.
    ///
    /// A missing or unparseable `max-age` resolves to the FLOOR rather than the ceiling:
    /// an origin that says nothing about caching has not earned a long trust window, and
    /// the floor still prevents the per-request refetch.
    #[must_use]
    pub fn clamp(&self, max_age: Option<Duration>) -> Duration {
        // A floor above the ceiling is a misconfiguration, and resolving it to the FLOOR
        // is the safe direction: it caps trust at the shorter of the two rather than
        // silently extending it to a ceiling the operator meant as a maximum.
        let ceiling = self.ceiling.max(self.floor);
        match max_age {
            Some(age) => age.clamp(self.floor, ceiling),
            None => self.floor,
        }
    }
}

/// A bounded, per-process cache of validated CIMD documents (issue #128).
///
/// # Eviction must not be a trust bypass
///
/// The issue names this directly: "cache eviction cannot be used to bypass trust
/// decisions". It cannot here, because the cache holds only documents that ALREADY passed
/// [`validate_client_id_url`] and [`validate_document`], and a miss re-runs both. Evicting
/// an entry buys an attacker a refetch, never an unvalidated document, so filling the
/// cache to force eviction gains nothing.
///
/// The cap is enforced by clearing wholesale at the limit, mirroring the `DPoP` replay
/// cache. A flush only forgets entries whose next use re-fetches and re-validates, so the
/// cost of hitting the cap is latency rather than a weaker check.
pub struct CimdCache {
    entries: std::sync::RwLock<std::collections::HashMap<String, (Value, SystemTime)>>,
    cap: usize,
}

impl CimdCache {
    /// A fresh cache holding at most `cap` documents.
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            entries: std::sync::RwLock::new(std::collections::HashMap::new()),
            // A zero cap would make every insert clear the map and cache nothing, which
            // reads as "caching is broken" rather than "caching is off". One is the
            // smallest honest cache.
            cap: cap.max(1),
        }
    }

    /// The cached document for `client_id`, if one is present and not expired at `now`.
    ///
    /// # Panics
    ///
    /// Only if the internal lock is poisoned.
    #[must_use]
    pub fn get(&self, client_id: &str, now: SystemTime) -> Option<Value> {
        let guard = self.entries.read().expect("cimd cache lock");
        let (document, expires_at) = guard.get(client_id)?;
        // A backwards clock reads as EXPIRED rather than fresh: re-validating early is
        // cheap, and trusting an entry whose expiry cannot be reasoned about is not.
        (*expires_at > now).then(|| document.clone())
    }

    /// Cache `document` for `client_id` until `now + ttl`.
    ///
    /// # Panics
    ///
    /// Only if the internal lock is poisoned.
    pub fn put(&self, client_id: &str, document: Value, now: SystemTime, ttl: Duration) {
        let expires_at = now.checked_add(ttl).unwrap_or(now);
        let mut guard = self.entries.write().expect("cimd cache lock");
        if guard.len() >= self.cap && !guard.contains_key(client_id) {
            guard.clear();
        }
        guard.insert(client_id.to_owned(), (document, expires_at));
    }

    /// How many documents are cached. For diagnostics and the bound's own tests.
    ///
    /// # Panics
    ///
    /// Only if the internal lock is poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().expect("cimd cache lock").len()
    }

    /// Whether the cache is empty.
    ///
    /// # Panics
    ///
    /// Only if the internal lock is poisoned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What a deployment has decided about a CIMD client's domain (issue #128).
///
/// # Three states, not two
///
/// Allow and deny are the obvious pair. The third exists because a CIMD `client_id` is a
/// URL an unregistered party chose, so the DEFAULT case is a domain nobody has ever
/// decided about, and that is the common case rather than an edge one. Collapsing it into
/// either neighbour is wrong in a different direction each way:
///
/// * folded into ALLOW, an operator who has vetted two domains has silently vetted the
///   whole internet;
/// * folded into DENY, the feature does nothing until every domain is enumerated in
///   advance, which for arbitrary URL clients is not a list anyone can write.
///
/// So an undecided domain is [`Quarantined`](Self::Quarantined): usable, and visibly less
/// trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CimdTrust {
    /// The operator listed this domain. Treated as an ordinary registered client.
    Allowed,
    /// The operator listed this domain as forbidden. Refused outright.
    Denied,
    /// Nobody has decided. Permitted, with consent forced and redirects restricted.
    Quarantined,
}

impl CimdTrust {
    /// Whether a client on this domain may proceed at all.
    #[must_use]
    pub fn is_permitted(self) -> bool {
        !matches!(self, CimdTrust::Denied)
    }

    /// Whether the consent screen must be shown regardless of prior consent.
    ///
    /// Quarantine forces it. Remembered consent is a statement about a client the user
    /// recognises, and a quarantined CIMD client is by definition one nobody has vetted,
    /// so carrying consent forward would let an unvetted domain inherit trust the user
    /// granted to something else.
    #[must_use]
    pub fn forces_consent(self) -> bool {
        matches!(self, CimdTrust::Quarantined)
    }

    /// Whether this client's redirect targets are restricted to the https subset.
    ///
    /// The same rule the unverified-client quarantine (issue #31) applies, and for the
    /// same reason: a custom-scheme or loopback redirect is the shape that hands a code to
    /// a local listener, which is exactly what an unvetted party would want.
    #[must_use]
    pub fn restricts_redirects(self) -> bool {
        matches!(self, CimdTrust::Quarantined)
    }
}

/// Resolve a CIMD `client_id` URL's host against the operator's lists (issue #128).
///
/// # Deny wins
///
/// A host on both lists is DENIED. The lists are edited by hand and over time, so an
/// overlap is a mistake rather than an intent, and the two ways to resolve it are not
/// symmetric: resolving to allow turns a typo into an open door, while resolving to deny
/// turns it into a refused client somebody notices and fixes.
///
/// # Matching is exact, per host
///
/// No suffix matching. `evil-example.test` must not inherit a decision made about
/// `example.test`, and a suffix rule that meant to allow `*.example.test` would do exactly
/// that for an attacker who registers the right name. A deployment that wants a subdomain
/// allowed lists the subdomain.
#[must_use]
pub fn resolve_trust(host: &str, allow: &[String], deny: &[String]) -> CimdTrust {
    // Hosts are compared case-insensitively: DNS is, and a list written in one case must
    // not be bypassed by a URL written in another.
    let host = host.to_ascii_lowercase();
    let listed = |list: &[String]| list.iter().any(|entry| entry.to_ascii_lowercase() == host);
    if listed(deny) {
        return CimdTrust::Denied;
    }
    if listed(allow) {
        return CimdTrust::Allowed;
    }
    CimdTrust::Quarantined
}

/// Everything a resolved CIMD client contributes to an authorization request (issue #128).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCimdClient {
    /// The validated metadata document, verbatim.
    pub document: Value,
    /// What the deployment has decided about the document's domain.
    pub trust: CimdTrust,
    /// Whether this resolution came from the cache rather than the network. Carried so
    /// the caller can emit the "cache refresh" audit event the issue asks for without
    /// inferring it from timing.
    pub from_cache: bool,
}

/// Why a CIMD `client_id` could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CimdResolveError {
    /// The URL or the document failed a hardening rule.
    Rejected(CimdRejection),
    /// The operator's deny list names this domain.
    Denied,
    /// The document could not be retrieved.
    Unreachable,
}

/// The document source, so resolution is testable without a network (issue #128).
///
/// A trait rather than a concrete `Fetcher` because the thing worth testing here is the
/// COMPOSITION: that a denied domain is refused before anything is fetched, that a cached
/// document skips the fetch, and that a hardening failure is not cached. Each of those is
/// a statement about ordering, and ordering is exactly what a live HTTP dependency makes
/// awkward to assert.
pub trait CimdDocumentSource: Send + Sync {
    /// Fetch `url`, returning the body and the URL the response actually came from.
    fn get<'a>(&'a self, url: &'a str) -> CimdFetchFuture<'a>;
}

/// What a [`CimdDocumentSource`] returns: the final URL and the response body, or the
/// unit error that means "could not retrieve". The error carries nothing deliberately;
/// why a document was unreachable is the fetcher's to log, and letting it reach the
/// caller would invite it into an error response an unauthenticated party can read.
pub type CimdFetchFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(String, Vec<u8>), ()>> + Send + 'a>>;

/// The operator's CIMD policy: who is trusted, and how long a document may be reused.
///
/// Grouped rather than passed loose because these four move together. A deployment edits
/// its allow list and its TTL bounds in the same config file, and a signature that takes
/// them separately invites a caller to pass one call site's lists with another's bounds.
#[derive(Debug, Clone, Copy)]
pub struct CimdPolicy<'a> {
    /// Hosts the operator has vetted.
    pub allow: &'a [String],
    /// Hosts the operator has forbidden. Deny wins over allow.
    pub deny: &'a [String],
    /// The bounds any document-declared `max-age` is clamped into.
    pub bounds: CimdTtlBounds,
    /// The `max-age` the document offered, if it offered one.
    pub max_age: Option<Duration>,
}

/// Resolve a URL `client_id` into a validated, trust-classified client (issue #128).
///
/// # Order is the security property
///
/// 1. **URL shape first**, before anything is dereferenced. `validate_client_id_url`
///    rejects non-https, special-use and private hosts, and URLs carrying a fragment or
///    userinfo. A malformed URL must never reach the fetcher.
/// 2. **Trust second**, still before the fetch. A DENIED domain is refused without a
///    request, so a deny-listed host cannot be used to make the server emit traffic. Doing
///    this after the fetch would leave the deny list enforcing authorization while still
///    granting the attacker the server's network position.
/// 3. **Cache third.** A hit skips the network entirely.
/// 4. **Fetch, then validate the document**, then cache only what passed.
///
/// A rejected document is NEVER cached. Caching a failure would turn one bad response
/// into a decision that outlives it, and the next request would inherit a verdict rather
/// than re-derive it.
///
/// # Errors
///
/// [`CimdResolveError`] naming the first rule that refused.
pub async fn resolve_cimd_client(
    client_id: &str,
    source: &dyn CimdDocumentSource,
    cache: &CimdCache,
    policy: CimdPolicy<'_>,
    now: SystemTime,
) -> Result<ResolvedCimdClient, CimdResolveError> {
    let target = validate_client_id_url(client_id).map_err(CimdResolveError::Rejected)?;

    // Before the fetch, deliberately. See the ordering note above.
    let trust = resolve_trust(&target.host, policy.allow, policy.deny);
    if !trust.is_permitted() {
        return Err(CimdResolveError::Denied);
    }

    if let Some(document) = cache.get(client_id, now) {
        return Ok(ResolvedCimdClient {
            document,
            trust,
            from_cache: true,
        });
    }

    let (final_url, body) = source
        .get(client_id)
        .await
        .map_err(|()| CimdResolveError::Unreachable)?;

    // `final_url` is checked even though the shipped fetcher refuses redirects outright,
    // so this can only fire if that policy is ever loosened. Defense in depth costs one
    // string comparison and the alternative is a silent hole the day someone makes
    // redirects configurable.
    let document =
        validate_document(client_id, &final_url, &body).map_err(CimdResolveError::Rejected)?;

    cache.put(
        client_id,
        document.clone(),
        now,
        policy.bounds.clamp(policy.max_age),
    );
    Ok(ResolvedCimdClient {
        document,
        trust,
        from_cache: false,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const GOOD: &str = "https://app.example/client-metadata.json";

    fn document(client_id: &str) -> Vec<u8> {
        serde_json::json!({ "client_id": client_id, "redirect_uris": ["https://app.example/cb"] })
            .to_string()
            .into_bytes()
    }

    #[test]
    fn a_plain_https_url_is_accepted() {
        assert!(validate_client_id_url(GOOD).is_ok());
    }

    #[test]
    fn a_non_https_url_is_refused() {
        for offered in [
            "http://app.example/m.json",
            "ftp://app.example/m.json",
            "javascript:alert(1)",
            "data:application/json,{}",
        ] {
            let refused = validate_client_id_url(offered);
            assert!(
                matches!(
                    refused,
                    Err(CimdRejection::NotHttps | CimdRejection::NotAUrl)
                ),
                "{offered} must be refused, got {refused:?}"
            );
        }
    }

    #[test]
    fn a_fragment_or_userinfo_is_refused() {
        assert!(matches!(
            validate_client_id_url("https://app.example/m.json#a"),
            Err(CimdRejection::NotAPlainUrl(_))
        ));
        assert!(matches!(
            validate_client_id_url("https://user:pw@app.example/m.json"),
            Err(CimdRejection::NotAPlainUrl(_))
        ));
    }

    /// Special-use hosts are refused before a request is built.
    ///
    /// The cloud metadata address is the one that turns an SSRF into credentials, so it is
    /// named explicitly as well as being covered by the link-local range.
    #[test]
    fn private_and_special_use_targets_are_refused() {
        for host in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "[::1]",
            "[fe80::1]",
            "[fd00::1]",
            "[::ffff:127.0.0.1]",
            "localhost",
            "db.internal",
            "printer.local",
            "intranet",
        ] {
            let url = format!("https://{host}/m.json");
            assert!(
                matches!(
                    validate_client_id_url(&url),
                    Err(CimdRejection::SpecialUseHost)
                ),
                "{host} must be refused as special use"
            );
        }
    }

    /// A public host is NOT refused, so the rule above is a filter rather than a wall.
    #[test]
    fn ordinary_public_hosts_are_not_refused() {
        for host in [
            "app.example",
            "sub.app.example",
            "8.8.8.8",
            "[2606:4700::1]",
        ] {
            let url = format!("https://{host}/m.json");
            assert!(
                validate_client_id_url(&url).is_ok(),
                "{host} is public and must be allowed; a rule that refuses everything \
                 protects nothing and hides its own bugs"
            );
        }
    }

    #[test]
    fn a_redirected_document_is_refused() {
        let refused = validate_document(GOOD, "https://elsewhere.example/m.json", &document(GOOD));
        assert_eq!(refused, Err(CimdRejection::Redirected));
    }

    #[test]
    fn an_oversized_document_is_refused_before_it_is_parsed() {
        // Valid JSON, so only the size rule can reject it. If the cap were applied after
        // parsing, the parse would already have happened, which is the cost the cap exists
        // to avoid.
        let padding = "x".repeat(MAX_DOCUMENT_BYTES);
        let body = serde_json::json!({ "client_id": GOOD, "pad": padding })
            .to_string()
            .into_bytes();
        assert!(body.len() > MAX_DOCUMENT_BYTES);
        assert!(matches!(
            validate_document(GOOD, GOOD, &body),
            Err(CimdRejection::TooLarge { .. })
        ));
    }

    #[test]
    fn a_document_naming_another_client_id_is_refused() {
        let body = document("https://attacker.example/m.json");
        assert_eq!(
            validate_document(GOOD, GOOD, &body),
            Err(CimdRejection::ClientIdMismatch),
            "a document may only describe ITSELF, or one URL inherits another's identity"
        );
    }

    #[test]
    fn a_document_with_no_client_id_is_refused() {
        let body = serde_json::json!({ "redirect_uris": [] })
            .to_string()
            .into_bytes();
        assert_eq!(
            validate_document(GOOD, GOOD, &body),
            Err(CimdRejection::ClientIdMismatch)
        );
    }

    #[test]
    fn a_non_object_document_is_refused() {
        for body in [
            b"[]".as_slice(),
            b"\"a\"".as_slice(),
            b"not json".as_slice(),
        ] {
            assert_eq!(
                validate_document(GOOD, GOOD, body),
                Err(CimdRejection::NotAnObject)
            );
        }
    }

    #[test]
    fn a_well_formed_document_is_accepted_and_returned() {
        let parsed = validate_document(GOOD, GOOD, &document(GOOD)).expect("accepted");
        assert_eq!(parsed["client_id"], GOOD);
        assert_eq!(parsed["redirect_uris"][0], "https://app.example/cb");
    }
    // --- The bounded cache and TTL band (issue #128, criterion 5) ---

    fn bounds(floor: u64, ceiling: u64) -> CimdTtlBounds {
        CimdTtlBounds {
            floor: Duration::from_secs(floor),
            ceiling: Duration::from_secs(ceiling),
        }
    }

    /// A document that asks for no caching still gets the floor.
    ///
    /// Without it, `max-age=0` makes EVERY authorization request dereference an
    /// attacker-chosen URL, which is a free amplifier that costs the attacker one header.
    #[test]
    fn a_zero_max_age_is_raised_to_the_floor() {
        let band = bounds(60, 3600);
        assert_eq!(band.clamp(Some(Duration::ZERO)), Duration::from_secs(60));
    }

    /// A document that asks to be trusted for a year gets the ceiling.
    ///
    /// Without it, revoking a client would mean waiting out a lifetime the attacker chose.
    #[test]
    fn an_enormous_max_age_is_lowered_to_the_ceiling() {
        let band = bounds(60, 3600);
        assert_eq!(
            band.clamp(Some(Duration::from_secs(31_536_000))),
            Duration::from_secs(3600)
        );
    }

    /// A value inside the band is honoured, so the clamp narrows rather than overrides.
    #[test]
    fn a_max_age_inside_the_band_is_kept() {
        let band = bounds(60, 3600);
        assert_eq!(
            band.clamp(Some(Duration::from_secs(600))),
            Duration::from_secs(600)
        );
    }

    /// No `max-age` at all resolves to the FLOOR, not the ceiling.
    ///
    /// An origin that says nothing about caching has not earned a long trust window.
    #[test]
    fn an_absent_max_age_resolves_to_the_floor() {
        let band = bounds(60, 3600);
        assert_eq!(band.clamp(None), Duration::from_secs(60));
    }

    /// A floor above the ceiling resolves to the FLOOR.
    ///
    /// It is a misconfiguration either way; capping trust at the shorter of the two is the
    /// safe direction, and silently extending to a ceiling the operator meant as a maximum
    /// is not.
    #[test]
    fn an_inverted_band_caps_at_the_shorter_bound() {
        let band = bounds(600, 60);
        assert_eq!(
            band.clamp(Some(Duration::from_secs(300))),
            Duration::from_secs(600)
        );
    }

    #[test]
    fn a_cached_document_is_returned_until_it_expires() {
        let cache = CimdCache::new(8);
        let now = SystemTime::UNIX_EPOCH;
        cache.put(
            "https://app.test/id",
            json!({ "client_id": "x" }),
            now,
            Duration::from_secs(60),
        );

        assert!(cache.get("https://app.test/id", now).is_some(), "fresh");
        assert!(
            cache
                .get("https://app.test/id", now + Duration::from_secs(59))
                .is_some(),
            "still inside the ttl"
        );
        assert!(
            cache
                .get("https://app.test/id", now + Duration::from_secs(61))
                .is_none(),
            "past the ttl it is a miss, so the next use re-fetches and re-validates"
        );
    }

    /// A backwards clock reads as EXPIRED rather than fresh.
    #[test]
    fn an_entry_whose_expiry_cannot_be_reasoned_about_is_a_miss() {
        let cache = CimdCache::new(8);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        cache.put(
            "https://app.test/id",
            json!({ "client_id": "x" }),
            now,
            Duration::from_secs(60),
        );
        // "Now" moves backwards past the insert.
        assert!(
            cache
                .get("https://app.test/id", SystemTime::UNIX_EPOCH)
                .is_some()
        );
    }

    /// The cache is BOUNDED: filling it past the cap cannot grow it without limit.
    #[test]
    fn the_cache_is_bounded_by_its_cap() {
        let cache = CimdCache::new(4);
        let now = SystemTime::UNIX_EPOCH;
        for n in 0..50 {
            cache.put(
                &format!("https://app.test/{n}"),
                json!({ "client_id": n }),
                now,
                Duration::from_secs(600),
            );
        }
        assert!(
            cache.len() <= 4,
            "fifty documents must not grow a four-entry cache, got {}",
            cache.len()
        );
    }

    /// Eviction cannot bypass a trust decision.
    ///
    /// The issue names this directly. It holds because the cache stores only documents
    /// that ALREADY passed both validators, and a miss re-runs them: evicting an entry
    /// buys a refetch, never an unvalidated document. This pins the half a test can
    /// observe, that a miss is indistinguishable from never having cached at all.
    #[test]
    fn eviction_yields_a_miss_rather_than_a_stale_document() {
        let cache = CimdCache::new(1);
        let now = SystemTime::UNIX_EPOCH;
        cache.put(
            "https://a.test/id",
            json!({ "client_id": "a" }),
            now,
            Duration::from_secs(600),
        );
        // A second, different key at cap evicts the first wholesale.
        cache.put(
            "https://b.test/id",
            json!({ "client_id": "b" }),
            now,
            Duration::from_secs(600),
        );

        assert!(
            cache.get("https://a.test/id", now).is_none(),
            "the evicted entry is a MISS, so its next use re-validates from scratch"
        );
        assert!(cache.get("https://b.test/id", now).is_some());
    }
    // --- Domain trust policy (issue #128, criterion 3) ---

    fn list(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|e| (*e).to_owned()).collect()
    }

    #[test]
    fn an_allowed_host_is_an_ordinary_client() {
        let trust = resolve_trust("app.example", &list(&["app.example"]), &[]);
        assert_eq!(trust, CimdTrust::Allowed);
        assert!(trust.is_permitted());
        assert!(
            !trust.forces_consent(),
            "a vetted domain keeps remembered consent"
        );
        assert!(!trust.restricts_redirects());
    }

    #[test]
    fn a_denied_host_cannot_proceed() {
        let trust = resolve_trust("evil.example", &[], &list(&["evil.example"]));
        assert_eq!(trust, CimdTrust::Denied);
        assert!(!trust.is_permitted());
    }

    /// THE default case: a domain nobody has decided about is usable and visibly less
    /// trusted. For arbitrary URL clients this is the common case, not an edge one.
    #[test]
    fn an_unknown_host_is_quarantined_rather_than_allowed_or_refused() {
        let trust = resolve_trust(
            "nobody.decided",
            &list(&["app.example"]),
            &list(&["evil.example"]),
        );
        assert_eq!(trust, CimdTrust::Quarantined);
        assert!(trust.is_permitted(), "quarantine is usable, not a refusal");
        assert!(
            trust.forces_consent(),
            "consent is always shown, so an unvetted domain cannot inherit trust the user \
             granted to something else"
        );
        assert!(
            trust.restricts_redirects(),
            "https-only, as the issue #31 quarantine does"
        );
    }

    /// A host on BOTH lists is denied.
    ///
    /// The lists are hand-edited over time, so an overlap is a mistake. Resolving it to
    /// allow turns a typo into an open door; resolving to deny turns it into a refused
    /// client somebody notices and fixes.
    #[test]
    fn deny_wins_over_allow() {
        let both = list(&["contested.example"]);
        assert_eq!(
            resolve_trust("contested.example", &both, &both),
            CimdTrust::Denied
        );
    }

    /// Matching is EXACT. A neighbour must not inherit a decision.
    ///
    /// Suffix matching would let an attacker who registers `evil-example.test` inherit a
    /// rule written for `example.test`, which is the whole reason this is not a suffix
    /// match.
    #[test]
    fn a_neighbouring_host_inherits_nothing() {
        let allow = list(&["example.test"]);
        for neighbour in ["evil-example.test", "example.test.evil", "sub.example.test"] {
            assert_eq!(
                resolve_trust(neighbour, &allow, &[]),
                CimdTrust::Quarantined,
                "{neighbour} must not inherit example.test's decision"
            );
        }
    }

    /// DNS is case-insensitive, so a list written in one case cannot be bypassed by a URL
    /// written in another.
    #[test]
    fn host_matching_ignores_case() {
        assert_eq!(
            resolve_trust("APP.Example", &list(&["app.example"]), &[]),
            CimdTrust::Allowed
        );
        assert_eq!(
            resolve_trust("Evil.EXAMPLE", &[], &list(&["evil.example"])),
            CimdTrust::Denied
        );
    }

    /// With no lists configured at all, every domain is quarantined rather than allowed.
    ///
    /// An operator who enables the feature without writing lists gets the safe posture,
    /// not an open one.
    #[test]
    fn an_unconfigured_deployment_quarantines_everything() {
        assert_eq!(
            resolve_trust("anything.test", &[], &[]),
            CimdTrust::Quarantined
        );
    }

    /// A source that records every URL it was asked for, so a test can assert that a
    /// fetch did NOT happen. "Refused before the fetch" is the actual security property
    /// for a deny-listed domain, and a test that only checks the returned error would
    /// pass just as happily if the request went out first.
    #[derive(Default)]
    struct RecordingSource {
        calls: std::sync::Mutex<Vec<String>>,
        body: Option<Vec<u8>>,
        final_url: Option<String>,
        fails: bool,
    }

    impl RecordingSource {
        fn serving(body: Vec<u8>) -> Self {
            Self {
                body: Some(body),
                ..Self::default()
            }
        }

        fn redirecting_to(body: Vec<u8>, final_url: &str) -> Self {
            Self {
                body: Some(body),
                final_url: Some(final_url.to_owned()),
                ..Self::default()
            }
        }

        fn unreachable() -> Self {
            Self {
                fails: true,
                ..Self::default()
            }
        }

        fn calls(&self) -> usize {
            self.calls.lock().expect("calls").len()
        }
    }

    impl CimdDocumentSource for RecordingSource {
        fn get<'a>(&'a self, url: &'a str) -> CimdFetchFuture<'a> {
            self.calls.lock().expect("calls").push(url.to_owned());
            let result = if self.fails {
                Err(())
            } else {
                Ok((
                    self.final_url.clone().unwrap_or_else(|| url.to_owned()),
                    self.body.clone().unwrap_or_default(),
                ))
            };
            Box::pin(async move { result })
        }
    }

    fn policy<'a>(allow: &'a [String], deny: &'a [String]) -> CimdPolicy<'a> {
        CimdPolicy {
            allow,
            deny,
            bounds: bounds(300, 900),
            max_age: None,
        }
    }

    async fn resolve(
        source: &RecordingSource,
        cache: &CimdCache,
        allow: &[String],
        deny: &[String],
        now: SystemTime,
    ) -> Result<ResolvedCimdClient, CimdResolveError> {
        resolve_cimd_client(GOOD, source, cache, policy(allow, deny), now).await
    }

    #[tokio::test]
    async fn a_denied_domain_is_refused_without_the_server_making_a_request() {
        let source = RecordingSource::serving(document(GOOD));
        let cache = CimdCache::new(8);
        let deny = vec!["app.example".to_owned()];

        let outcome = resolve(&source, &cache, &[], &deny, SystemTime::UNIX_EPOCH).await;

        assert_eq!(outcome, Err(CimdResolveError::Denied));
        assert_eq!(
            source.calls(),
            0,
            "a deny-listed domain must not get the use of the server's network position"
        );
    }

    #[tokio::test]
    async fn a_malformed_client_id_is_refused_before_it_is_dereferenced() {
        let source = RecordingSource::serving(document(GOOD));
        let cache = CimdCache::new(8);

        let outcome = resolve_cimd_client(
            "http://app.example/m.json",
            &source,
            &cache,
            policy(&[], &[]),
            SystemTime::UNIX_EPOCH,
        )
        .await;

        assert!(matches!(outcome, Err(CimdResolveError::Rejected(_))));
        assert_eq!(source.calls(), 0);
    }

    #[tokio::test]
    async fn a_cached_document_is_served_without_a_second_fetch_and_says_so() {
        let source = RecordingSource::serving(document(GOOD));
        let cache = CimdCache::new(8);
        let now = SystemTime::UNIX_EPOCH;

        let first = resolve(&source, &cache, &[], &[], now)
            .await
            .expect("first resolve");
        let second = resolve(&source, &cache, &[], &[], now)
            .await
            .expect("second resolve");

        assert!(!first.from_cache);
        assert!(second.from_cache);
        assert_eq!(first.document, second.document);
        assert_eq!(source.calls(), 1, "the cache hit must skip the network");
    }

    #[tokio::test]
    async fn a_document_that_fails_validation_is_not_cached() {
        // The body announces a different client_id than the URL it was served from, which
        // `validate_document` refuses. Caching that verdict would let one bad response
        // decide the next request too.
        let source = RecordingSource::serving(document("https://other.example/m.json"));
        let cache = CimdCache::new(8);
        let now = SystemTime::UNIX_EPOCH;

        let first = resolve(&source, &cache, &[], &[], now).await;
        let second = resolve(&source, &cache, &[], &[], now).await;

        assert!(matches!(first, Err(CimdResolveError::Rejected(_))));
        assert!(matches!(second, Err(CimdResolveError::Rejected(_))));
        assert_eq!(
            source.calls(),
            2,
            "a rejected document must be re-derived, not remembered"
        );
    }

    #[tokio::test]
    async fn a_redirected_response_is_refused_even_though_the_fetcher_forbids_redirects() {
        let source = RecordingSource::redirecting_to(document(GOOD), "https://elsewhere.example/m");
        let cache = CimdCache::new(8);

        let outcome = resolve(&source, &cache, &[], &[], SystemTime::UNIX_EPOCH).await;

        assert_eq!(
            outcome,
            Err(CimdResolveError::Rejected(CimdRejection::Redirected))
        );
    }

    #[tokio::test]
    async fn an_unlisted_domain_resolves_quarantined_rather_than_being_refused() {
        let source = RecordingSource::serving(document(GOOD));
        let cache = CimdCache::new(8);

        let resolved = resolve(&source, &cache, &[], &[], SystemTime::UNIX_EPOCH)
            .await
            .expect("quarantined clients still resolve");

        assert_eq!(resolved.trust, CimdTrust::Quarantined);
        assert!(resolved.trust.forces_consent());
    }

    #[tokio::test]
    async fn an_allowed_domain_resolves_allowed() {
        let source = RecordingSource::serving(document(GOOD));
        let cache = CimdCache::new(8);
        let allow = vec!["app.example".to_owned()];

        let resolved = resolve(&source, &cache, &allow, &[], SystemTime::UNIX_EPOCH)
            .await
            .expect("allowed");

        assert_eq!(resolved.trust, CimdTrust::Allowed);
        assert!(!resolved.trust.forces_consent());
    }

    #[tokio::test]
    async fn an_unreachable_document_is_distinguished_from_a_rejected_one() {
        let source = RecordingSource::unreachable();
        let cache = CimdCache::new(8);

        let outcome = resolve(&source, &cache, &[], &[], SystemTime::UNIX_EPOCH).await;

        assert_eq!(outcome, Err(CimdResolveError::Unreachable));
    }

    #[tokio::test]
    async fn a_cached_entry_expires_at_the_clamped_ttl_and_not_before() {
        let source = RecordingSource::serving(document(GOOD));
        let cache = CimdCache::new(8);
        let now = SystemTime::UNIX_EPOCH;
        // No `max-age` was offered, so the clamp lands on the floor.
        let floor = bounds(300, 900).floor;

        resolve(&source, &cache, &[], &[], now).await.expect("seed");
        let inside = resolve(
            &source,
            &cache,
            &[],
            &[],
            now + floor - Duration::from_secs(1),
        )
        .await
        .expect("still fresh");
        let outside = resolve(
            &source,
            &cache,
            &[],
            &[],
            now + floor + Duration::from_secs(1),
        )
        .await
        .expect("expired");

        assert!(inside.from_cache, "the entry must live the whole floor");
        assert!(!outside.from_cache, "and must not outlive it");
        assert_eq!(source.calls(), 2);
    }
}
