// SPDX-License-Identifier: MIT OR Apache-2.0

//! Trusted-header SSO for a forward-auth surface (issue #154 criterion 2).
//!
//! A reverse proxy asks this surface whether to admit a request. On an admission the upstream
//! application is told WHO the caller is through headers it trusts: `Remote-User`,
//! `Remote-Groups`, `Remote-Email`, `Remote-Name`. The application reads them and believes
//! them, because by construction they can only have come from the authenticator.
//!
//! That last clause is the entire security property, and it has two halves that fail in
//! opposite directions:
//!
//! - **Nothing reaches the upstream unless the decision was an allow.** A denial that still
//!   emitted `Remote-User` would hand the application an identity for a request it was told
//!   to refuse.
//! - **Nothing the CLIENT sent under those names influences anything.** A caller who sets
//!   `Remote-User: admin` and reaches an upstream that trusts the header has authenticated as
//!   anyone, with no bug anywhere in the authenticator.
//!
//! # What this module enforces, and what it does not
//!
//! It enforces that IronAuth's own decision never sees a reserved header the client sent, and
//! that the headers it emits come only from the authenticator. It CANNOT delete anything from
//! the request the proxy forwards: that is the proxy's configuration, which is criterion 1's
//! work. [`ForwardAuthOutcome::must_delete`] is therefore an INSTRUCTION to the dialect
//! adapter, not a record of something already done. A dialect that sets-if-present rather
//! than delete-then-set leaves a forged header in place, and the naming here is deliberate so
//! that is hard to miss.
//!
//! # Why stripping happens before evaluation, not after
//!
//! It would be enough for the second half to strip on the way out. It is not enough for
//! correctness: the rules engine reads request headers, so a client-supplied `Remote-Groups:
//! admins` could satisfy a rule written about the header the upstream trusts. Stripping on
//! input means a rule can never be evaluated against a value the client chose for a name the
//! system reserves.

use crate::rules::{Action, Decision, RequestFacts, RuleSet};

/// The trusted headers, each paired with the identity field it carries.
///
/// ONE list, read by both the emitter and the reservation check. They were separate, and
/// nothing tied them: a fifth emitted header could be added without becoming reserved, which
/// is a silent forgery hole with no check anywhere. Deriving both from this makes that
/// impossible rather than merely unlikely.
/// How one trusted header reads its value out of an [`Identity`].
type ReadField = fn(&Identity) -> Option<String>;

const TRUSTED: [(&str, ReadField); 4] = [
    ("Remote-User", |identity| Some(identity.user.clone())),
    ("Remote-Groups", |identity| Some(identity.groups.join(","))),
    ("Remote-Email", |identity| identity.email.clone()),
    ("Remote-Name", |identity| identity.name.clone()),
];

/// The header names reserved for the authenticator, as emitted.
pub fn trusted_header_names() -> impl Iterator<Item = &'static str> {
    TRUSTED.iter().map(|(name, _)| *name)
}

/// The canonical form of a header name for the reservation check.
///
/// Lowercased, underscores folded to hyphens, surrounding whitespace removed.
///
/// # Why more than a case fold
///
/// `eq_ignore_ascii_case` on the exact name let `Remote_User` through, and a review then used
/// a rule naming `Remote_Groups` to let a client-chosen value decide a request. To any
/// `CGI`, `FastCGI`, `WSGI` or PHP upstream, `Remote_User` and `Remote-User` are the SAME variable
/// (`HTTP_REMOTE_USER`), and those self-hosted applications are exactly the class forward-auth
/// exists to protect. Leading and trailing whitespace is stripped for the same reason: a
/// parser that trims before lookup would see the reserved name.
fn canonical_header_name(name: &str) -> String {
    name.trim()
        .chars()
        .map(|c| {
            if c == '_' {
                '-'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

/// Whether `name` is reserved for the authenticator.
#[must_use]
pub fn is_trusted_header(name: &str) -> bool {
    let canonical = canonical_header_name(name);
    trusted_header_names().any(|reserved| canonical_header_name(reserved) == canonical)
}

/// Why an identity cannot be sent to an upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// A field carries a byte that cannot appear in a header value.
    ///
    /// Carrying a carriage return or newline is request splitting: `alice\r\nRemote-Groups:
    /// admins` becomes a second header the upstream reads as authoritative.
    ControlCharacter {
        /// The field that carries it.
        field: &'static str,
    },
    /// A group name contains the separator that joins the list.
    ///
    /// One group literally named `users,admins` is byte-identical on the wire to membership
    /// in two groups. Directory-synced group display names are not charset-restricted, so
    /// `Finance, EU` is an ordinary name rather than an exotic one.
    SeparatorInGroup {
        /// The offending group.
        group: String,
    },
    /// The subject is empty, which an upstream would read as a user named nothing.
    EmptySubject,
}

/// What the authenticator knows about the caller.
///
/// Built from the session, never from the request, which is the point.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    /// The subject identifier.
    pub user: String,
    /// Group memberships. A group name may not contain a comma; see [`IdentityError`].
    pub groups: Vec<String>,
    /// Role memberships, for rules that check roles.
    pub roles: Vec<String>,
    /// The verified email address, if the deployment has one.
    pub email: Option<String>,
    /// The display name, if the deployment has one.
    pub name: Option<String>,
    /// The authentication context class this identity's session ACHIEVED, absent when the
    /// surface that built it does not resolve one.
    ///
    /// Derived from the session's recorded method tokens, never from the request. It rides on
    /// the identity rather than arriving beside it so that the engine's view of how strongly
    /// the caller authenticated comes from the SAME resolution as who they are: those two
    /// disagreeing is how a rule authorises one principal and the upstream is told about
    /// another, which the subject, groups and roles were already consolidated here to prevent.
    ///
    /// [`None`] never satisfies an ACR floor and never resolves a step-up, so a surface that
    /// has not wired this challenges rather than admits.
    pub acr: Option<String>,
}

impl Identity {
    /// Whether this identity can be serialised into headers safely.
    ///
    /// # Errors
    ///
    /// [`IdentityError`] naming the first problem found.
    pub fn validate(&self) -> Result<(), IdentityError> {
        if self.user.is_empty() {
            return Err(IdentityError::EmptySubject);
        }
        let forbidden = |value: &str| value.chars().any(char::is_control);
        if forbidden(&self.user) {
            return Err(IdentityError::ControlCharacter { field: "user" });
        }
        for group in &self.groups {
            if forbidden(group) {
                return Err(IdentityError::ControlCharacter { field: "groups" });
            }
            if group.contains(',') {
                return Err(IdentityError::SeparatorInGroup {
                    group: group.clone(),
                });
            }
        }
        for role in &self.roles {
            if forbidden(role) {
                return Err(IdentityError::ControlCharacter { field: "roles" });
            }
        }
        if self.email.as_deref().is_some_and(forbidden) {
            return Err(IdentityError::ControlCharacter { field: "email" });
        }
        if self.name.as_deref().is_some_and(forbidden) {
            return Err(IdentityError::ControlCharacter { field: "name" });
        }
        Ok(())
    }
}

/// What a forward-auth surface answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardAuthOutcome {
    /// The access decision.
    pub decision: Decision,
    /// Headers to ADD to the upstream request. Empty unless the decision was an allow.
    pub upstream_headers: Vec<(String, String)>,
    /// Header names the dialect adapter MUST DELETE from the forwarded request.
    ///
    /// An instruction, not a record. This module removed them from its own view of the
    /// request so no rule could be evaluated against one; whether the client's forged header
    /// reaches the upstream depends on the proxy, which this module does not configure.
    ///
    /// Surfaced rather than dropped silently for a second reason: a client sending
    /// `Remote-User` is either a misconfigured proxy or an attempt to forge an identity, and
    /// an operator wants to know which without reproducing it.
    pub must_delete: Vec<String>,
    /// Set when an identity was supplied that cannot be sent to an upstream.
    ///
    /// The decision is forced to [`Action::Deny`] in that case. A silently dropped header
    /// while the admission stands is worse than a refusal: the upstream would serve the
    /// request as some OTHER principal, or as none.
    pub identity_rejected: Option<IdentityError>,
}

/// A forward-auth surface over a rule set.
///
/// Holds the rules privately and exposes no accessor for them. An earlier version had one,
/// and it handed a caller holding the sanitising surface a reference that skips sanitising.
pub struct ForwardAuth {
    rules: RuleSet,
}

impl ForwardAuth {
    /// Build a surface over `rules`.
    #[must_use]
    pub fn new(rules: RuleSet) -> Self {
        Self { rules }
    }

    /// Decide `facts`, and say what the upstream should be told.
    ///
    /// `facts` is taken by value and sanitised here, so this surface cannot evaluate an
    /// unsanitised request. That is a property of THIS function, not of the crate: the rules
    /// engine's own entry points take a [`RequestFacts`] whose fields are public, so a
    /// deployment that calls them directly is not protected by anything here. Route
    /// forward-auth traffic through this function.
    ///
    /// # The principal is taken from `identity`, not from `facts`
    ///
    /// The subject, groups and roles the engine decides about are OVERWRITTEN from
    /// `identity`. They were independent inputs, and a review authorised `alice` on her group
    /// membership while telling the upstream it was serving `mallory`. There is now one
    /// principal, so the two cannot disagree.
    #[must_use]
    pub fn evaluate(&self, facts: RequestFacts, identity: Option<&Identity>) -> ForwardAuthOutcome {
        let (mut facts, must_delete) = strip_trusted_headers(facts);

        // An identity that cannot be serialised is a refusal, not a silent drop.
        if let Some(problem) = identity.and_then(|identity| identity.validate().err()) {
            return ForwardAuthOutcome {
                decision: Decision::no_match(),
                upstream_headers: Vec::new(),
                must_delete,
                identity_rejected: Some(problem),
            };
        }

        // ONE principal: what the engine decides about is what the upstream is told.
        facts.subject = identity.map(|identity| identity.user.clone());
        facts.groups = identity
            .map(|identity| identity.groups.clone())
            .unwrap_or_default();
        facts.roles = identity
            .map(|identity| identity.roles.clone())
            .unwrap_or_default();
        // THE SAME OVERWRITE, for the same reason. A caller-supplied acr would answer the
        // step-up challenge made of it; taking it from the resolved identity means the only
        // thing that can satisfy a step-up rule is an authentication that happened.
        facts.acr = identity.and_then(|identity| identity.acr.clone());

        let decision = self.rules.decide(&facts);

        // ONLY an allow forwards anything. A step-up is not an admission: the caller has to
        // come back with stronger authentication, and handing the upstream an identity in the
        // meantime would defeat the requirement being made.
        let upstream_headers = match (&decision.action, identity) {
            (Action::Allow, Some(identity)) => upstream_headers_for(identity),
            (Action::Allow, None) | (Action::Deny | Action::StepUp { .. }, _) => Vec::new(),
        };

        ForwardAuthOutcome {
            decision,
            upstream_headers,
            must_delete,
            identity_rejected: None,
        }
    }
}

/// Combine repeated header names per RFC 9110 rather than keeping the last.
///
/// ONE implementation, called by both adapters. It lived only inside `facts_from_proxy`, and
/// the dialect path grew its own `collect()` that kept whichever entry came last, so the same
/// request decided differently depending on which door it came through.
fn combine_repeated<I>(headers: I) -> std::collections::HashMap<String, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut combined: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (name, value) in headers {
        combined
            .entry(name)
            .and_modify(|existing| {
                existing.push_str(", ");
                existing.push_str(&value);
            })
            .or_insert(value);
    }
    combined
}

/// The host with any port removed, refusing anything that is not one host.
///
/// `RequestFacts::host` documents itself as "the host, without port" and nothing enforced it.
/// Traefik sets `X-Forwarded-Host` from the request Host, which carries a non-default port,
/// so a host rule silently stopped matching; a chained proxy comma-appends, which makes the
/// value ambiguous rather than merely decorated.
///
/// A port is STRIPPED, because the rule's contract says the host carries none and the proxy
/// is not wrong to send one. A comma-joined list is REFUSED, because choosing among them is a
/// guess and `Criterion::Host` is exact equality, so a wrong guess is a rule that matches the
/// wrong deployment.
fn host_without_port(host: &str) -> Result<String, DialectError> {
    if host.is_empty() || host.contains(',') || host.chars().any(char::is_control) {
        return Err(DialectError::MalformedHost);
    }
    let bare = match host.rsplit_once(':') {
        Some((left, right)) if !right.is_empty() && right.chars().all(|c| c.is_ascii_digit()) => {
            left
        }
        _ => host,
    };
    if bare.is_empty() {
        return Err(DialectError::MalformedHost);
    }
    Ok(bare.to_owned())
}

/// Remove every reserved header the client sent, returning the sanitised facts and the names
/// the adapter must delete.
///
/// Returns the names as the CLIENT spelled them, because that is what an operator needs in
/// order to recognise the proxy or the caller responsible.
#[must_use]
pub fn strip_trusted_headers(mut facts: RequestFacts) -> (RequestFacts, Vec<String>) {
    let mut reserved: Vec<String> = facts
        .headers
        .keys()
        .filter(|name| is_trusted_header(name))
        .cloned()
        .collect();
    // Sorted so the report is stable: `HashMap` iteration order is not, and a log line that
    // reorders itself between identical requests is one nobody can diff.
    reserved.sort_unstable();
    for name in &reserved {
        facts.headers.remove(name);
    }
    (facts, reserved)
}

/// The headers an upstream application should receive for `identity`.
///
/// Private on purpose. It was public, and it takes no decision, so it sat beside the allow
/// gate offering the same output without it. The only way to obtain these headers is through
/// [`ForwardAuth::evaluate`], which applies the gate.
///
/// Absent optional fields are OMITTED rather than sent empty, so an upstream can tell "no
/// email on this account" from "an empty email", which are different facts. Note the
/// interaction recorded on [`ForwardAuthOutcome::must_delete`]: omitting is only safe on a
/// dialect that deletes before setting.
fn upstream_headers_for(identity: &Identity) -> Vec<(String, String)> {
    TRUSTED
        .iter()
        .filter_map(|(name, read)| read(identity).map(|value| ((*name).to_owned(), value)))
        .collect()
}

/// Build request facts from a proxy's forwarded description of the original request.
///
/// Sanitises on the way in, so a dialect adapter cannot forget to.
///
/// Repeated header names are COMBINED with `, ` rather than last-wins. HTTP permits
/// repetition and the criterion names header smuggling through untrusted hops as an attack
/// class; a lossy collect let an adapter's ordering decide which value a rule saw, so a rule
/// denying on `X-Internal: yes` was evadable by sending the header twice. Combining is the
/// RFC 9110 reading and it fails toward NOT matching an exact-value rule, which is the
/// refusing direction.
#[must_use]
pub fn facts_from_proxy<I>(
    method: &str,
    host: &str,
    path: &str,
    headers: I,
) -> (RequestFacts, Vec<String>)
where
    I: IntoIterator<Item = (String, String)>,
{
    let combined = combine_repeated(headers);
    strip_trusted_headers(RequestFacts {
        method: method.to_owned(),
        host: host.to_owned(),
        path: path.to_owned(),
        headers: combined,
        ..RequestFacts::default()
    })
}

// ===========================================================================
// Proxy dialects (issue #154 criterion 1, the dialect-independent half).
// ===========================================================================

/// How a proxy describes the ORIGINAL request when it asks this surface to decide.
///
/// Each dialect names a different set of headers for the same three facts: the method, the
/// host, and the path of the request the client actually made. The check request itself is
/// addressed to the authenticator, so its own method and path say nothing about what is
/// being authorised.
///
/// # The dialect IS a trust boundary
///
/// These headers decide which rule matches. A caller who sets `X-Forwarded-Uri: /public` on
/// a request for `/admin` and reaches a surface that believes it has chosen its own
/// authorization path. They are safe to read only when the request arrived through a hop the
/// operator configured as trusted, which is what [`ProxyHop`] carries.
///
/// # Why the header NAMES are per dialect rather than a union
///
/// Reading any recognised original-URI header regardless of dialect is the smuggling case the
/// criterion names: a deployment behind nginx, which sets `X-Original-URI`, would also honour
/// an `X-Forwarded-Uri` that nginx never sets and never strips, so a client could supply one
/// directly. A dialect reads its OWN names and ignores the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// Traefik and Caddy forward-auth: `X-Forwarded-Method`, `X-Forwarded-Host`,
    /// `X-Forwarded-Uri`.
    ForwardAuth,
    /// nginx `auth_request`: `X-Original-Method`, `X-Original-URI`, host from the INHERITED
    /// `Host`.
    ///
    /// Not `X-Forwarded-Host`: the subrequest inherits `Host`, and requiring the forwarded
    /// one made correctly configured proxies refuse every request. See [`Self::host_header`].
    /// Note that `proxy_pass` rewrites `Host` to `$proxy_host` unless the location sets
    /// `proxy_set_header Host $host`.
    NginxAuthRequest,
    /// Envoy and Istio `ext_authz` over HTTP: the check request carries the original method
    /// and path as its OWN method and path, with the host on `X-Forwarded-Host`.
    EnvoyExtAuthz,
    /// `HAProxy`: `X-Forwarded-Method`, `X-Forwarded-Host`, `X-Forwarded-Uri`.
    ///
    /// NOT `X-Original-URI`. That is what this line used to say, and
    /// [`Self::uri_header`] records why it changed: `HAProxy` neither sets nor strips
    /// `X-Original-URI`, so reading it let a client supply one directly and choose its own
    /// authorization path.
    Haproxy,
}

/// Whether the check request arrived through a hop the operator trusts.
///
/// A separate type rather than a `bool` argument, so a call site cannot pass the wrong one by
/// having the arguments in the wrong order. The decision itself belongs to the server's
/// trusted-proxy policy, which already fails closed on any ambiguity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyHop {
    /// The immediate peer is a configured proxy.
    Trusted,
    /// It is not, or the policy could not tell.
    Untrusted,
}

/// Why a check request could not be turned into a decidable description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialectError {
    /// The request did not arrive through a trusted hop, so nothing it says about the
    /// original request can be believed.
    UntrustedHop,
    /// A header this dialect needs is absent.
    Missing {
        /// The header name.
        header: &'static str,
    },
    /// A header this dialect needs appeared more than once with different values.
    ///
    /// The smuggling case: a proxy sets one and a client supplies another, and whichever the
    /// parser happens to pick decides the authorization. There is no safe pick, so this is a
    /// refusal rather than a choice.
    Conflicting {
        /// The header name.
        header: &'static str,
    },
    /// The original URI is not something a path rule can be evaluated against.
    ///
    /// Includes a percent-encoded path: this engine has no decoder, so a path it cannot read
    /// is a path it cannot authorise.
    MalformedUri,
    /// The original host is not a single host a rule can be compared against.
    MalformedHost,
}

impl Dialect {
    /// The header this dialect reads the original METHOD from, if any.
    #[must_use]
    pub const fn method_header(self) -> Option<&'static str> {
        match self {
            Dialect::ForwardAuth | Dialect::Haproxy => Some("x-forwarded-method"),
            Dialect::NginxAuthRequest => Some("x-original-method"),
            // Envoy's check request IS the original method.
            Dialect::EnvoyExtAuthz => None,
        }
    }

    /// The header this dialect reads the original URI from, if any.
    #[must_use]
    pub const fn uri_header(self) -> Option<&'static str> {
        match self {
            // HAProxy sends X-Forwarded-URI, the same as Traefik and Caddy. This row said
            // `x-original-uri`, a header HAProxy neither sets nor strips, so on a real
            // deployment a client supplies it directly and chooses its own authorization
            // path. That is this module's own argument aimed at its own row, and a review
            // demonstrated the bypass end to end.
            Dialect::ForwardAuth | Dialect::Haproxy => Some("x-forwarded-uri"),
            Dialect::NginxAuthRequest => Some("x-original-uri"),
            Dialect::EnvoyExtAuthz => None,
        }
    }

    /// The header this dialect reads the original HOST from.
    ///
    /// NOT the same for every dialect, though it was. `x-forwarded-host` is what the
    /// `X-Forwarded-*` family carries, and Envoy's `ext_authz` check request does not include
    /// it: the proto includes `Host`, `Method`, `Path`, `Content-Length` and `Authorization`
    /// and nothing else by default. nginx's `auth_request` sets no headers at all, so a
    /// deployment following the nginx.org example sends `X-Original-URI` and the ordinary
    /// `Host`.
    ///
    /// Requiring `x-forwarded-host` from all four made two of them refuse EVERY request from
    /// a correctly configured proxy. Fail closed, so not a bypass, and invisible to every
    /// test because each fixture supplied the header by construction.
    #[must_use]
    pub const fn host_header(self) -> &'static str {
        match self {
            // The X-Forwarded family carries the host in its own header.
            Dialect::ForwardAuth | Dialect::Haproxy => "x-forwarded-host",
            // Envoy's check request carries the original Host; nginx's auth_request
            // subrequest inherits it.
            Dialect::EnvoyExtAuthz | Dialect::NginxAuthRequest => "host",
        }
    }

    /// Turn a check request into facts a rule can be evaluated against.
    ///
    /// `check_method` and `check_path` are the check request's own, which only
    /// [`Dialect::EnvoyExtAuthz`] treats as the original.
    ///
    /// Reserved identity headers are stripped here as well, so no path exists that builds
    /// facts from a proxy without sanitising them.
    ///
    /// # Errors
    ///
    /// [`DialectError`] when the hop is untrusted, a needed header is absent or conflicting,
    /// or the URI cannot be read.
    pub fn describe(
        self,
        hop: ProxyHop,
        check_method: &str,
        check_path: &str,
        headers: &[(String, String)],
    ) -> Result<(RequestFacts, Vec<String>), DialectError> {
        // FIRST, before reading anything the request says about itself. An untrusted hop
        // means every header below is attacker-supplied, and there is no subset of them worth
        // reading: the answer is not "fall back to the check request's own path", because
        // that is the authenticator's path and authorising it would authorise the wrong
        // resource.
        if hop == ProxyHop::Untrusted {
            return Err(DialectError::UntrustedHop);
        }

        let one = |name: &'static str| -> Result<Option<String>, DialectError> {
            let mut seen: Option<&str> = None;
            for (key, value) in headers {
                if !key.eq_ignore_ascii_case(name) {
                    continue;
                }
                match seen {
                    Some(first) if first != value => {
                        return Err(DialectError::Conflicting { header: name });
                    }
                    _ => seen = Some(value),
                }
            }
            Ok(seen.map(str::to_owned))
        };

        let method = match self.method_header() {
            Some(name) => one(name)?.ok_or(DialectError::Missing { header: name })?,
            None => check_method.to_owned(),
        };
        let path = match self.uri_header() {
            Some(name) => one(name)?.ok_or(DialectError::Missing { header: name })?,
            None => check_path.to_owned(),
        };
        let host = one(self.host_header())?.ok_or(DialectError::Missing {
            header: self.host_header(),
        })?;

        // The URI may carry a query or a fragment, neither of which a path criterion should
        // see. Both are split, and a test covers each: the fragment half was untested and a
        // mutant removing it survived.
        let path = path.split(['?', '#']).next().unwrap_or_default().to_owned();
        if !path.starts_with('/') || path.contains("..") {
            return Err(DialectError::MalformedUri);
        }
        // AN ENCODED PATH IS ONE THIS ENGINE CANNOT DECIDE.
        //
        // `contains("..")` is a literal byte scan, so `%2e%2e`, `%2E%2E`, `.%2e` and
        // `%252e%252e` all walked past it, and a proxy delivers the encoded form verbatim
        // (Traefik sets `X-Forwarded-Uri` from the raw request URI; nginx's `$request_uri`
        // is documented as unmodified) while the origin decodes and normalises to `/admin`.
        // A review took `/public/%2e%2e/admin/keys` through a rule allowing `/public` and got
        // an admission.
        //
        // Decoding here would mean writing a normaliser that has to agree with whatever the
        // ORIGIN does, which is a different program per upstream. Refusing is the honest
        // answer: this engine has no decoder, so a path it cannot read is a path it cannot
        // authorise, and a deployment that needs encoded paths needs a decision about whose
        // normalisation wins before it needs a rule.
        if path.contains('%') {
            return Err(DialectError::MalformedUri);
        }
        // Control characters, which reach a trace, a log line, or a redirect parameter.
        if path.chars().any(char::is_control) {
            return Err(DialectError::MalformedUri);
        }
        // A bound, because nothing else imposes one and a rule engine is not the place to
        // discover that a proxy will forward a megabyte of path.
        if path.len() > 4096 {
            return Err(DialectError::MalformedUri);
        }

        // COMBINED, not last-wins. `headers.iter().cloned().collect()` into a `HashMap`
        // keeps whichever entry comes last, which is the exact defect `facts_from_proxy` was
        // fixed for forty lines below and documents: an adapter's ordering decided which
        // value a rule saw, so a rule denying on a header was evadable by sending it twice.
        // This path reintroduced it while the PR claimed the dialect path was not a second
        // way in that skips what the other one does. It stripped reserved headers and
        // dropped the combine.
        let facts = RequestFacts {
            method,
            host: host_without_port(&host)?,
            path,
            headers: combine_repeated(headers.iter().cloned()),
            ..RequestFacts::default()
        };
        Ok(strip_trusted_headers(facts))
    }
}

#[cfg(test)]
mod tests {
    use crate::rules::{Criterion, Rule, SubjectCheck};

    use super::*;

    fn identity() -> Identity {
        Identity {
            user: "alice".to_owned(),
            groups: vec!["engineering".to_owned(), "oncall".to_owned()],
            roles: Vec::new(),
            email: Some("alice@example.test".to_owned()),
            name: Some("Alice".to_owned()),
            acr: None,
        }
    }

    fn rule(name: &str, criteria: Vec<Criterion>, action: Action) -> Rule {
        Rule {
            name: name.to_owned(),
            criteria,
            action,
        }
    }

    fn open() -> ForwardAuth {
        ForwardAuth::new(RuleSet::new(vec![rule("open", vec![], Action::Allow)]))
    }

    /// A rule set that admits ONLY when a reserved header carries a chosen value, with a
    /// trailing deny. This is the fixture that can see stripping: if a client-supplied
    /// reserved header reaches the engine, the first rule matches and the answer flips.
    fn gated_on(name: &str) -> ForwardAuth {
        ForwardAuth::new(RuleSet::new(vec![
            rule(
                "reserved-header-gate",
                vec![Criterion::Header {
                    name: name.to_owned(),
                    value: "admins".to_owned(),
                }],
                Action::Allow,
            ),
            rule("default-deny", vec![], Action::Deny),
        ]))
    }

    fn request_with(name: &str, value: &str) -> RequestFacts {
        let mut facts = RequestFacts {
            method: "GET".to_owned(),
            host: "app.example.test".to_owned(),
            path: "/".to_owned(),
            ..RequestFacts::default()
        };
        facts.headers.insert(name.to_owned(), value.to_owned());
        facts
    }

    /// A CLIENT-SUPPLIED RESERVED HEADER CANNOT DECIDE A REQUEST, in any spelling.
    ///
    /// This replaces a test that asserted the forged value was absent from
    /// `upstream_headers` while passing `identity: None`, which makes that vector
    /// unconditionally empty: the assertion could not fail for any implementation. A mutant
    /// that removed stripping entirely passed it.
    ///
    /// The fixture here admits only on the reserved header, so a surviving client value
    /// flips the decision. That is what makes it able to fail.
    #[test]
    fn a_client_supplied_reserved_header_never_decides_a_request() {
        for spelling in [
            "Remote-Groups",
            "remote-groups",
            "REMOTE-GROUPS",
            "ReMoTe-GrOuPs",
            // Same variable to any CGI, FastCGI, WSGI or PHP upstream.
            "Remote_Groups",
            "REMOTE_GROUPS",
            // A parser that trims before lookup sees the reserved name.
            " Remote-Groups",
            "Remote-Groups ",
        ] {
            let outcome =
                gated_on("Remote-Groups").evaluate(request_with(spelling, "admins"), None);
            assert_eq!(
                outcome.decision.action,
                Action::Deny,
                "{spelling}: a client-chosen value must not satisfy a rule on a reserved name"
            );
            assert_eq!(
                outcome.decision.matched.as_deref(),
                Some("default-deny"),
                "{spelling}: and it must fall through to the deny"
            );
            assert_eq!(
                outcome.must_delete,
                vec![spelling.to_owned()],
                "{spelling}: and the adapter is told to delete it"
            );
        }
    }

    /// EVERY EMITTED HEADER NAME IS RESERVED.
    ///
    /// Derived from the EMITTER rather than from the reserved list. The previous version
    /// iterated `TRUSTED_HEADERS` and asserted against `TRUSTED_HEADERS`, so a missing entry,
    /// a duplicate, or a typo corrupted the expectation along with the code. A review
    /// duplicated an entry so `Remote-Name` was forgeable, and this test passed.
    #[test]
    fn every_header_the_emitter_can_send_is_reserved_against_the_client() {
        let full = Identity {
            user: "u".to_owned(),
            groups: vec!["g".to_owned()],
            roles: vec!["r".to_owned()],
            email: Some("e@example.test".to_owned()),
            name: Some("n".to_owned()),
            acr: None,
        };
        let emitted = upstream_headers_for(&full);
        assert_eq!(
            emitted.len(),
            4,
            "all four fields are populated in this fixture"
        );

        for (name, _) in &emitted {
            assert!(
                is_trusted_header(name),
                "{name} is emitted upstream but a client could send it"
            );
        }

        // And the names are distinct: a duplicated entry would silently drop one field.
        let mut names: Vec<&str> = emitted.iter().map(|(name, _)| name.as_str()).collect();
        names.sort_unstable();
        let distinct = names.len();
        names.dedup();
        assert_eq!(names.len(), distinct, "two entries share a header name");
    }

    /// AN INVALID IDENTITY IS A REFUSAL, not a silently dropped header.
    ///
    /// A carriage return in a subject is request splitting: the upstream reads the injected
    /// line as an authoritative header. Dropping it while the admission stands would serve
    /// the request as some other principal, or as none.
    #[test]
    fn an_identity_that_cannot_be_serialised_is_refused() {
        let cases = [
            (
                "crlf in the subject",
                Identity {
                    user: "alice\r\nRemote-Groups: admins".to_owned(),
                    ..identity()
                },
                IdentityError::ControlCharacter { field: "user" },
            ),
            (
                "newline in the display name",
                Identity {
                    name: Some("A\nB".to_owned()),
                    acr: None,
                    ..identity()
                },
                IdentityError::ControlCharacter { field: "name" },
            ),
            (
                "crlf in the email",
                Identity {
                    email: Some("a@b\r\nX-Admin: 1".to_owned()),
                    ..identity()
                },
                IdentityError::ControlCharacter { field: "email" },
            ),
            (
                "a comma inside one group name",
                Identity {
                    groups: vec!["Finance, EU".to_owned()],
                    ..identity()
                },
                IdentityError::SeparatorInGroup {
                    group: "Finance, EU".to_owned(),
                },
            ),
            (
                "an empty subject",
                Identity {
                    user: String::new(),
                    ..identity()
                },
                IdentityError::EmptySubject,
            ),
        ];

        for (what, bad, expected) in cases {
            let outcome = open().evaluate(request_with("X-Other", "kept"), Some(&bad));
            assert_eq!(
                outcome.identity_rejected.as_ref(),
                Some(&expected),
                "{what}: must be rejected by name"
            );
            assert_eq!(
                outcome.decision.action,
                Action::Deny,
                "{what}: and the request refused, not admitted with a missing header"
            );
            assert!(outcome.upstream_headers.is_empty(), "{what}");
        }
    }

    /// ONE GROUP NAMED `a,b` IS NOT TWO GROUPS.
    ///
    /// On the wire the join makes them byte-identical, so an upstream splitting on commas
    /// reads a single directory-synced group named `Finance, EU` as membership in two.
    #[test]
    fn a_comma_in_a_group_name_cannot_forge_a_second_membership() {
        let one = Identity {
            groups: vec!["users,admins".to_owned()],
            ..identity()
        };
        let two = Identity {
            groups: vec!["users".to_owned(), "admins".to_owned()],
            ..identity()
        };
        assert_eq!(
            one.validate(),
            Err(IdentityError::SeparatorInGroup {
                group: "users,admins".to_owned()
            })
        );
        assert_eq!(
            two.validate(),
            Ok(()),
            "the genuine two-group case still works"
        );
    }

    /// THE ENGINE DECIDES ABOUT THE PRINCIPAL THAT IS FORWARDED.
    ///
    /// They were independent inputs. A review authorised `alice` on her group membership and
    /// told the upstream it was serving `mallory`, a member of `admins`.
    #[test]
    fn the_decided_principal_is_the_forwarded_principal() {
        let gated = ForwardAuth::new(RuleSet::new(vec![
            rule(
                "engineering-only",
                vec![Criterion::Subject(SubjectCheck::InGroup(
                    "engineering".to_owned(),
                ))],
                Action::Allow,
            ),
            rule("default-deny", vec![], Action::Deny),
        ]));

        // Facts claim alice/engineering; the authenticator says mallory/admins.
        let mut facts = request_with("X-Other", "kept");
        facts.subject = Some("alice".to_owned());
        facts.groups = vec!["engineering".to_owned()];
        let mallory = Identity {
            user: "mallory".to_owned(),
            groups: vec!["admins".to_owned(), "finance".to_owned()],
            roles: Vec::new(),
            email: None,
            name: None,
            acr: None,
        };

        let outcome = gated.evaluate(facts, Some(&mallory));
        assert_eq!(
            outcome.decision.action,
            Action::Deny,
            "the decision must be about mallory, who is not in engineering"
        );
        assert!(outcome.upstream_headers.is_empty());

        // And the converse: the real member is admitted and forwarded as herself.
        let engineer = Identity {
            user: "alice".to_owned(),
            groups: vec!["engineering".to_owned()],
            roles: Vec::new(),
            email: None,
            name: None,
            acr: None,
        };
        let outcome = gated.evaluate(request_with("X-Other", "kept"), Some(&engineer));
        assert_eq!(outcome.decision.action, Action::Allow);
        assert_eq!(
            outcome.upstream_headers[0],
            ("Remote-User".to_owned(), "alice".to_owned())
        );
    }

    /// A DENIAL FORWARDS NOTHING, even with a fully authenticated identity in hand.
    #[test]
    fn a_denied_request_forwards_no_identity() {
        let shut = ForwardAuth::new(RuleSet::new(vec![rule("shut", vec![], Action::Deny)]));
        let outcome = shut.evaluate(request_with("X-Other", "kept"), Some(&identity()));
        assert_eq!(outcome.decision.action, Action::Deny);
        assert!(
            outcome.upstream_headers.is_empty(),
            "a refusal must not hand the upstream an identity for a request it was told to refuse"
        );
    }

    /// A STEP-UP FORWARDS NOTHING EITHER. It is not an admission.
    #[test]
    fn a_step_up_forwards_no_identity() {
        let stepped = ForwardAuth::new(RuleSet::new(vec![rule(
            "mfa",
            vec![],
            Action::StepUp {
                acr: "mfa".to_owned(),
            },
        )]));
        let outcome = stepped.evaluate(request_with("X-Other", "kept"), Some(&identity()));
        assert_eq!(
            outcome.decision.action,
            Action::StepUp {
                acr: "mfa".to_owned()
            }
        );
        assert!(outcome.upstream_headers.is_empty());
    }

    /// AN ADMISSION FORWARDS THE AUTHENTICATOR'S VIEW, and only that.
    #[test]
    fn an_allowed_request_forwards_the_established_identity() {
        let outcome = open().evaluate(request_with("Remote-User", "root"), Some(&identity()));
        assert_eq!(outcome.decision.action, Action::Allow);
        assert_eq!(
            outcome.upstream_headers,
            vec![
                ("Remote-User".to_owned(), "alice".to_owned()),
                ("Remote-Groups".to_owned(), "engineering,oncall".to_owned()),
                ("Remote-Email".to_owned(), "alice@example.test".to_owned()),
                ("Remote-Name".to_owned(), "Alice".to_owned()),
            ]
        );
        assert_eq!(
            outcome.must_delete,
            vec!["Remote-User".to_owned()],
            "and the forged one is flagged for deletion by the adapter"
        );
    }

    /// AN ANONYMOUS ADMISSION FORWARDS NOTHING.
    #[test]
    fn an_anonymous_admission_forwards_no_identity() {
        let outcome = open().evaluate(request_with("X-Other", "kept"), None);
        assert_eq!(outcome.decision.action, Action::Allow);
        assert!(outcome.upstream_headers.is_empty());
    }

    /// AN ABSENT OPTIONAL FIELD IS OMITTED, not sent empty.
    #[test]
    fn absent_optional_fields_are_omitted_rather_than_blank() {
        let sparse = Identity {
            user: "bob".to_owned(),
            groups: Vec::new(),
            roles: Vec::new(),
            email: None,
            name: None,
            acr: None,
        };
        let headers = upstream_headers_for(&sparse);
        let names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, vec!["Remote-User", "Remote-Groups"]);
        assert_eq!(
            headers[1].1, "",
            "no groups is an empty list, which is a real answer, unlike a missing email"
        );
    }

    /// A NON-RESERVED HEADER IS LEFT ALONE.
    #[test]
    fn an_ordinary_header_is_not_stripped() {
        let outcome = gated_on("X-Service").evaluate(request_with("X-Service", "admins"), None);
        assert_eq!(
            outcome.decision.matched.as_deref(),
            Some("reserved-header-gate"),
            "an ordinary header must still reach a rule written about it"
        );
        assert!(outcome.must_delete.is_empty());
    }

    /// THE DELETION INSTRUCTION IS STABLE, so a log line does not reorder between requests.
    #[test]
    fn the_deletion_instruction_is_sorted() {
        let mut facts = request_with("Remote-User", "a");
        facts
            .headers
            .insert("Remote-Name".to_owned(), "b".to_owned());
        facts
            .headers
            .insert("Remote-Email".to_owned(), "c".to_owned());

        let first = strip_trusted_headers(facts.clone()).1;
        assert_eq!(
            first,
            vec![
                "Remote-Email".to_owned(),
                "Remote-Name".to_owned(),
                "Remote-User".to_owned()
            ]
        );
        for _ in 0..50 {
            assert_eq!(strip_trusted_headers(facts.clone()).1, first);
        }
    }

    /// THE PROXY ADAPTER SANITISES, and does not lose a repeated header.
    ///
    /// HTTP permits repetition, and the criterion names header smuggling through untrusted
    /// hops as an attack class. A last-wins collect let an adapter's ordering decide which
    /// value a rule saw, so a rule denying on a header was evadable by sending it twice.
    #[test]
    fn the_proxy_adapter_sanitises_and_combines_repeated_headers() {
        let (facts, must_delete) = facts_from_proxy(
            "GET",
            "app.example.test",
            "/",
            vec![
                ("remote-user".to_owned(), "root".to_owned()),
                ("x-service".to_owned(), "billing".to_owned()),
                ("x-service".to_owned(), "admin".to_owned()),
            ],
        );
        assert_eq!(must_delete, vec!["remote-user".to_owned()]);
        assert!(!facts.headers.contains_key("remote-user"));
        assert_eq!(
            facts.headers.get("x-service").map(String::as_str),
            Some("billing, admin"),
            "neither value may be dropped: an exact-value rule then matches neither, \
             which is the refusing direction"
        );
    }

    // -----------------------------------------------------------------------
    // Criterion 1, the dialect-independent half: the header-trust attack cases.
    // The container conformance matrix is the other half and needs real proxies.
    // -----------------------------------------------------------------------

    const ALL_DIALECTS: [Dialect; 4] = [
        Dialect::ForwardAuth,
        Dialect::NginxAuthRequest,
        Dialect::EnvoyExtAuthz,
        Dialect::Haproxy,
    ];

    /// A well-formed check request for `dialect`, describing `GET https://app/admin/keys`.
    fn check_for(dialect: Dialect) -> Vec<(String, String)> {
        let mut headers = vec![(
            dialect.host_header().to_owned(),
            "app.example.test".to_owned(),
        )];
        if let Some(name) = dialect.method_header() {
            headers.push((name.to_owned(), "GET".to_owned()));
        }
        if let Some(name) = dialect.uri_header() {
            headers.push((name.to_owned(), "/admin/keys".to_owned()));
        }
        headers
    }

    /// ATTACK 1: A CLIENT-CONTROLLED ORIGINAL-URI IS NEVER READ FROM AN UNTRUSTED HOP.
    ///
    /// This is the criterion's first named attack class. The refusal happens before any
    /// header is read, and the alternative is worse than it looks: falling back to the CHECK
    /// request's own path would authorise the authenticator's path rather than the resource,
    /// so a caller asking about `/admin` would be judged on `/verify`.
    #[test]
    fn an_untrusted_hop_is_refused_before_any_header_is_read() {
        for dialect in ALL_DIALECTS {
            let mut headers = check_for(dialect);
            // A caller claiming a harmless path for a request that is really for /admin.
            if let Some(name) = dialect.uri_header() {
                headers.retain(|(key, _)| key != name);
                headers.push((name.to_owned(), "/public/logo.png".to_owned()));
            }
            assert_eq!(
                dialect.describe(ProxyHop::Untrusted, "POST", "/verify", &headers),
                Err(DialectError::UntrustedHop),
                "{dialect:?}: an untrusted hop must be refused"
            );
        }
    }

    /// ATTACK 2: HEADER SMUGGLING THROUGH AN UNTRUSTED HOP.
    ///
    /// A proxy sets the original URI and a client supplies another. Whichever the parser
    /// happens to pick decides the authorization, and there is no safe pick, so a conflict is
    /// a refusal rather than a choice. Taking the first would trust the proxy on some
    /// stacks and the client on others.
    #[test]
    fn a_conflicting_original_uri_is_refused_rather_than_resolved() {
        for dialect in ALL_DIALECTS {
            let Some(name) = dialect.uri_header() else {
                continue;
            };
            let mut headers = check_for(dialect);
            headers.push((name.to_owned(), "/public/logo.png".to_owned()));
            assert_eq!(
                dialect.describe(ProxyHop::Trusted, "GET", "/verify", &headers),
                Err(DialectError::Conflicting { header: name }),
                "{dialect:?}: two different original URIs must refuse"
            );
        }
    }

    /// A REPEATED HEADER WITH THE SAME VALUE IS NOT A CONFLICT.
    ///
    /// The counterweight: refusing on repetition alone would break a proxy chain that sets
    /// the same value twice, which is ordinary, and an operator would disable the check.
    #[test]
    fn a_repeated_but_identical_header_is_accepted() {
        for dialect in ALL_DIALECTS {
            let Some(name) = dialect.uri_header() else {
                continue;
            };
            let mut headers = check_for(dialect);
            headers.push((name.to_owned(), "/admin/keys".to_owned()));
            let (facts, _) = dialect
                .describe(ProxyHop::Trusted, "GET", "/verify", &headers)
                .expect("identical repeats are not a conflict");
            assert_eq!(facts.path, "/admin/keys", "{dialect:?}");
        }
    }

    /// EACH DIALECT READS ITS OWN NAMES AND IGNORES THE OTHERS.
    ///
    /// Reading any recognised original-URI header regardless of dialect is the smuggling case
    /// in its most practical form: a deployment behind nginx, which sets `X-Original-URI`,
    /// would also honour an `X-Forwarded-Uri` that nginx never sets and therefore never
    /// strips, so a client could supply one directly.
    #[test]
    fn a_dialect_ignores_another_dialects_original_uri_header() {
        let foreign = [
            ("x-forwarded-uri", "/attacker/choice"),
            ("x-original-uri", "/attacker/choice"),
            ("x-forwarded-method", "DELETE"),
            ("x-original-method", "DELETE"),
        ];
        for dialect in ALL_DIALECTS {
            let mut headers = check_for(dialect);
            for (name, value) in foreign {
                if Some(name) == dialect.uri_header() || Some(name) == dialect.method_header() {
                    continue;
                }
                headers.push(((*name).to_owned(), (*value).to_owned()));
            }
            let (facts, _) = dialect
                .describe(ProxyHop::Trusted, "GET", "/admin/keys", &headers)
                .expect("the dialect's own headers are well formed");
            assert_eq!(
                facts.path, "/admin/keys",
                "{dialect:?}: another dialect's header must not decide the path"
            );
            assert_eq!(facts.method, "GET", "{dialect:?}: nor the method");
        }
    }

    /// A MISSING HEADER IS A REFUSAL, not an empty string.
    ///
    /// An empty path would match a rule written with an empty prefix, and would be reported
    /// in a trace as though the client had asked for it.
    #[test]
    fn a_missing_original_request_header_is_refused() {
        for dialect in ALL_DIALECTS {
            for name in [dialect.uri_header(), dialect.method_header()]
                .into_iter()
                .flatten()
            {
                let headers: Vec<(String, String)> = check_for(dialect)
                    .into_iter()
                    .filter(|(key, _)| key != name)
                    .collect();
                assert_eq!(
                    dialect.describe(ProxyHop::Trusted, "GET", "/admin/keys", &headers),
                    Err(DialectError::Missing { header: name }),
                    "{dialect:?}: a missing {name} must refuse"
                );
            }
            // And the host, which every dialect needs, under ITS OWN header name. This
            // hard-coded `x-forwarded-host`, which is only two of the four.
            let name = dialect.host_header();
            let headers: Vec<(String, String)> = check_for(dialect)
                .into_iter()
                .filter(|(key, _)| key != name)
                .collect();
            assert_eq!(
                dialect.describe(ProxyHop::Trusted, "GET", "/admin/keys", &headers),
                Err(DialectError::Missing { header: name }),
                "{dialect:?}"
            );
        }
    }

    /// A URI A PATH RULE CANNOT BE EVALUATED AGAINST IS REFUSED.
    ///
    /// Traversal is the one that matters: `/public/../admin` is `/admin` to a server and
    /// `/public/...` to a prefix rule, so admitting it authorises the wrong resource. A URI
    /// that is not a path at all is refused for the same reason: a rule written about paths
    /// cannot decide it.
    #[test]
    fn a_uri_a_path_rule_cannot_decide_is_refused() {
        for dialect in ALL_DIALECTS {
            for bad in [
                "/public/../admin/keys",
                "..",
                "admin/keys",
                "https://elsewhere.test/admin",
                "",
            ] {
                let mut headers = check_for(dialect);
                let (method, path) = ("GET", bad);
                if let Some(name) = dialect.uri_header() {
                    headers.retain(|(key, _)| key != name);
                    headers.push((name.to_owned(), bad.to_owned()));
                }
                let got = dialect.describe(ProxyHop::Trusted, method, path, &headers);
                assert_eq!(
                    got,
                    Err(DialectError::MalformedUri),
                    "{dialect:?}: {bad:?} must be refused"
                );
            }
        }
    }

    /// A QUERY STRING IS NOT PART OF THE PATH.
    ///
    /// A path criterion written for `/admin` must not be satisfied or defeated by what
    /// follows a `?`, and a rule set has a query criterion for the cases that need one.
    #[test]
    fn a_query_string_does_not_reach_the_path() {
        for dialect in ALL_DIALECTS {
            let mut headers = check_for(dialect);
            let with_query = "/admin/keys?next=/public";
            if let Some(name) = dialect.uri_header() {
                headers.retain(|(key, _)| key != name);
                headers.push((name.to_owned(), with_query.to_owned()));
            }
            let (facts, _) = dialect
                .describe(ProxyHop::Trusted, "GET", with_query, &headers)
                .expect("a query is not malformed");
            assert_eq!(facts.path, "/admin/keys", "{dialect:?}");
        }
    }

    /// THE DIALECT PATH SANITISES RESERVED HEADERS TOO.
    ///
    /// Otherwise it would be a second way into the engine that skips the stripping
    /// `ForwardAuth::evaluate` performs, which is the shape a review already found once in
    /// this module.
    #[test]
    fn a_dialect_strips_reserved_identity_headers() {
        for dialect in ALL_DIALECTS {
            let mut headers = check_for(dialect);
            headers.push(("Remote-User".to_owned(), "root".to_owned()));
            let (facts, stripped) = dialect
                .describe(ProxyHop::Trusted, "GET", "/admin/keys", &headers)
                .expect("well formed");
            assert_eq!(stripped, vec!["Remote-User".to_owned()], "{dialect:?}");
            assert!(
                !facts.headers.keys().any(|key| is_trusted_header(key)),
                "{dialect:?}: no reserved header may survive into the facts"
            );
        }
    }

    /// EVERY DIALECT PRODUCES THE SAME FACTS for the same original request.
    ///
    /// The point of supporting four: an operator's rules must not have to know which proxy is
    /// in front. A dialect that read a different path from an equivalent check request would
    /// make a rule set mean different things on different stacks.
    #[test]
    fn every_dialect_describes_one_original_request_identically() {
        let mut described = Vec::new();
        for dialect in ALL_DIALECTS {
            let (facts, _) = dialect
                .describe(ProxyHop::Trusted, "GET", "/admin/keys", &check_for(dialect))
                .expect("well formed");
            described.push((facts.method, facts.host, facts.path));
        }
        for (index, got) in described.iter().enumerate() {
            assert_eq!(
                got, &described[0],
                "dialect {index} describes the same request differently"
            );
        }
        assert_eq!(
            described[0],
            (
                "GET".to_owned(),
                "app.example.test".to_owned(),
                "/admin/keys".to_owned()
            )
        );
    }

    /// EACH DIALECT'S HEADER NAMES, PINNED TO LITERALS.
    ///
    /// Every other dialect test builds its fixture from `dialect.uri_header()` and
    /// `dialect.method_header()`, so changing the mapping changes the fixture with it and the
    /// suite stays green. A sweep proved it: pointing `NginxAuthRequest` at `x-forwarded-uri`
    /// left all of them passing, and that is a deployment reading a header nginx never sets
    /// and therefore never strips, which a client can supply directly.
    ///
    /// These are the names each proxy is conventionally configured to send. What the test
    /// fixes is not the convention but the SET: a dialect must read its own and no others.
    #[test]
    fn the_dialect_header_names_are_the_documented_ones() {
        assert_eq!(
            Dialect::ForwardAuth.method_header(),
            Some("x-forwarded-method")
        );
        assert_eq!(Dialect::ForwardAuth.uri_header(), Some("x-forwarded-uri"));

        assert_eq!(
            Dialect::NginxAuthRequest.method_header(),
            Some("x-original-method")
        );
        assert_eq!(
            Dialect::NginxAuthRequest.uri_header(),
            Some("x-original-uri"),
            "nginx sets x-original-uri; reading x-forwarded-uri here would honour a header \
             nginx never sets and never strips"
        );

        assert_eq!(
            Dialect::EnvoyExtAuthz.method_header(),
            None,
            "the ext_authz check request carries the original method as its own"
        );
        assert_eq!(Dialect::EnvoyExtAuthz.uri_header(), None);

        assert_eq!(Dialect::Haproxy.method_header(), Some("x-forwarded-method"));
        assert_eq!(
            Dialect::Haproxy.uri_header(),
            Some("x-forwarded-uri"),
            "HAProxy forward-auth sets X-Forwarded-Method, X-Forwarded-Host and \
             X-Forwarded-URI. This row said x-original-uri, which HAProxy neither sets nor \
             strips, so a client supplied it and chose its own path"
        );

        // The host header is NOT the same for every dialect, though it was, and requiring
        // x-forwarded-host from all four made Envoy and nginx refuse every real request.
        assert_eq!(Dialect::ForwardAuth.host_header(), "x-forwarded-host");
        assert_eq!(Dialect::Haproxy.host_header(), "x-forwarded-host");
        assert_eq!(
            Dialect::EnvoyExtAuthz.host_header(),
            "host",
            "ext_authz includes Host, Method, Path, Content-Length and Authorization by \
             default and nothing else"
        );
        assert_eq!(
            Dialect::NginxAuthRequest.host_header(),
            "host",
            "auth_request sets no headers; the subrequest inherits Host"
        );
    }

    /// A CONFLICT REFUSES ON EVERY HEADER IT GUARDS, not just the URI.
    ///
    /// `one()` is applied to the method, the host and the URI alike, and only the URI was
    /// tested: mutants turning the check off for the method and for the host both survived.
    #[test]
    fn a_conflict_on_any_original_request_header_is_refused() {
        for dialect in ALL_DIALECTS {
            // The host, which every dialect reads.
            let mut headers = check_for(dialect);
            headers.push((
                dialect.host_header().to_owned(),
                "elsewhere.test".to_owned(),
            ));
            assert_eq!(
                dialect.describe(ProxyHop::Trusted, "GET", "/admin/keys", &headers),
                Err(DialectError::Conflicting {
                    header: dialect.host_header()
                }),
                "{dialect:?}: two hosts must refuse"
            );

            if let Some(name) = dialect.method_header() {
                let mut headers = check_for(dialect);
                headers.push((name.to_owned(), "DELETE".to_owned()));
                assert_eq!(
                    dialect.describe(ProxyHop::Trusted, "GET", "/admin/keys", &headers),
                    Err(DialectError::Conflicting { header: name }),
                    "{dialect:?}: two methods must refuse"
                );
            }
        }
    }

    /// A PERCENT-ENCODED PATH IS REFUSED.
    ///
    /// `contains("..")` is a literal byte scan. A proxy forwards the encoded form verbatim
    /// and the origin decodes it, so `/public/%2e%2e/admin/keys` reached a rule allowing
    /// `/public` and was admitted. This engine has no decoder, so a path it cannot read is a
    /// path it cannot authorise.
    #[test]
    fn a_percent_encoded_path_is_refused_because_nothing_here_can_decode_it() {
        for dialect in ALL_DIALECTS {
            for encoded in [
                "/public/%2e%2e/admin/keys",
                "/public/%2E%2E/admin/keys",
                "/public/%2e%2e%2fadmin/keys",
                "/public/.%2e/admin/keys",
                "/public/%252e%252e/admin/keys",
                // Not traversal, but still undecidable by a rule written on decoded text.
                "/public/a%20b",
            ] {
                let mut headers = check_for(dialect);
                if let Some(name) = dialect.uri_header() {
                    headers.retain(|(key, _)| key != name);
                    headers.push((name.to_owned(), encoded.to_owned()));
                }
                assert_eq!(
                    dialect.describe(ProxyHop::Trusted, "GET", encoded, &headers),
                    Err(DialectError::MalformedUri),
                    "{dialect:?}: {encoded} must be refused"
                );
            }
        }
    }

    /// A CONTROL CHARACTER OR AN ABSURD LENGTH IS REFUSED.
    ///
    /// A newline in a path reaches a trace, a log line and a redirect parameter. Nothing
    /// bounded the length at all.
    #[test]
    fn a_path_that_cannot_safely_be_logged_or_bounded_is_refused() {
        let long = format!("/{}", "a".repeat(5000));
        for bad in [
            "/admin\u{0}/keys",
            "/admin\n/keys",
            "/admin\r\n/keys",
            &long,
        ] {
            let dialect = Dialect::ForwardAuth;
            let mut headers = check_for(dialect);
            headers.retain(|(key, _)| key != "x-forwarded-uri");
            headers.push(("x-forwarded-uri".to_owned(), bad.to_owned()));
            assert_eq!(
                dialect.describe(ProxyHop::Trusted, "GET", bad, &headers),
                Err(DialectError::MalformedUri),
                "{bad:?} must be refused"
            );
        }
    }

    /// A FRAGMENT IS SPLIT OFF THE PATH, like a query.
    ///
    /// The `'#'` half of the split was untested and a mutant removing it survived.
    #[test]
    fn a_fragment_does_not_reach_the_path() {
        for dialect in ALL_DIALECTS {
            let with_fragment = "/admin/keys#section";
            let mut headers = check_for(dialect);
            if let Some(name) = dialect.uri_header() {
                headers.retain(|(key, _)| key != name);
                headers.push((name.to_owned(), with_fragment.to_owned()));
            }
            let (facts, _) = dialect
                .describe(ProxyHop::Trusted, "GET", with_fragment, &headers)
                .expect("a fragment is not malformed");
            assert_eq!(facts.path, "/admin/keys", "{dialect:?}");
        }
    }

    /// THE HOST LOSES ITS PORT AND A COMMA-JOINED LIST IS REFUSED.
    ///
    /// `RequestFacts::host` says "the host, without port" and nothing enforced it. Traefik
    /// sets `X-Forwarded-Host` from the request Host, which carries a non-default port, so a
    /// host rule silently stopped matching; a chained proxy comma-appends, which is ambiguous
    /// rather than merely decorated.
    #[test]
    fn a_host_is_normalised_to_one_host_without_a_port() {
        let dialect = Dialect::ForwardAuth;
        for (sent, expected) in [
            ("app.example.test", "app.example.test"),
            ("app.example.test:8443", "app.example.test"),
            ("[2001:db8::1]:8443", "[2001:db8::1]"),
        ] {
            let mut headers = check_for(dialect);
            headers.retain(|(key, _)| key != "x-forwarded-host");
            headers.push(("x-forwarded-host".to_owned(), sent.to_owned()));
            let (facts, _) = dialect
                .describe(ProxyHop::Trusted, "GET", "/admin/keys", &headers)
                .expect("a port is not a refusal");
            assert_eq!(facts.host, expected, "{sent}");
        }

        for ambiguous in ["inner.test, app.example.test", ""] {
            let mut headers = check_for(dialect);
            headers.retain(|(key, _)| key != "x-forwarded-host");
            headers.push(("x-forwarded-host".to_owned(), ambiguous.to_owned()));
            let got = dialect.describe(ProxyHop::Trusted, "GET", "/admin/keys", &headers);
            assert!(
                matches!(
                    got,
                    Err(DialectError::MalformedHost | DialectError::Missing { .. })
                ),
                "{ambiguous:?} must not become a host a rule is compared against: {got:?}"
            );
        }
    }

    /// BOTH ADAPTERS COMBINE A REPEATED HEADER THE SAME WAY.
    ///
    /// The dialect path collected into a `HashMap`, which keeps the last entry, so the same
    /// request decided differently depending on which door it came through: a rule denying on
    /// a header was evadable by sending it twice.
    #[test]
    fn the_two_adapters_agree_about_a_repeated_header() {
        let dialect = Dialect::ForwardAuth;
        let mut headers = check_for(dialect);
        headers.push(("x-internal".to_owned(), "no".to_owned()));
        headers.push(("x-internal".to_owned(), "yes".to_owned()));

        let (via_dialect, _) = dialect
            .describe(ProxyHop::Trusted, "GET", "/admin/keys", &headers)
            .expect("well formed");
        let (via_adapter, _) = facts_from_proxy(
            "GET",
            "app.example.test",
            "/admin/keys",
            headers.iter().cloned(),
        );
        assert_eq!(
            via_dialect.headers.get("x-internal"),
            via_adapter.headers.get("x-internal"),
            "the two doors into the engine must not disagree"
        );
        assert_eq!(
            via_dialect.headers.get("x-internal").map(String::as_str),
            Some("no, yes"),
            "neither value may be dropped"
        );
    }

    /// THE CALLER CANNOT ANSWER THE STEP-UP MADE OF THEM.
    ///
    /// `RequestFacts::acr` is a public field on a struct the dialect adapters build, so the
    /// guarantee that it describes an authentication that HAPPENED lives here, in the same
    /// overwrite that consolidated the subject, groups and roles. Without it the requirement
    /// is handed to the party it constrains: a request stating `acr = mfa` satisfies a rule
    /// demanding mfa, and the step-up is decorative.
    ///
    /// Driven through `evaluate`, which is the surface every forward-auth request takes.
    #[test]
    fn the_reached_context_is_taken_from_the_identity_and_not_from_the_request() {
        let mfa = crate::step_up::canonical_step_up_acr("mfa");
        let pwd = crate::step_up::canonical_step_up_acr("pwd");
        let gate = ForwardAuth::new(RuleSet::new(vec![rule(
            "needs-mfa",
            vec![],
            Action::StepUp { acr: mfa.clone() },
        )]));

        let claiming = RequestFacts {
            method: "GET".to_owned(),
            host: "app.example.com".to_owned(),
            path: "/payments".to_owned(),
            acr: Some(mfa.clone()),
            ..RequestFacts::default()
        };

        let weak = Identity {
            acr: Some(pwd),
            ..identity()
        };
        assert_eq!(
            gate.evaluate(claiming.clone(), Some(&weak)).decision.action,
            Action::StepUp { acr: mfa.clone() },
            "a request asserting the context it was told to reach must still be challenged"
        );

        assert_eq!(
            gate.evaluate(claiming.clone(), None).decision.action,
            Action::StepUp { acr: mfa.clone() },
            "and an anonymous request asserting it must be challenged too, because the \
             overwrite clears the field rather than leaving what arrived"
        );

        let stepped_up = Identity {
            acr: Some(mfa.clone()),
            ..identity()
        };
        let admitted = gate.evaluate(
            RequestFacts {
                acr: None,
                ..claiming
            },
            Some(&stepped_up),
        );
        assert_eq!(
            admitted.decision.action,
            Action::Allow,
            "and the identity's context is what admits, even when the request stated none"
        );
        assert!(
            !admitted.upstream_headers.is_empty(),
            "an admission still forwards the identity"
        );
    }
}
