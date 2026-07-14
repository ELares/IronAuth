// SPDX-License-Identifier: MIT OR Apache-2.0

//! The grant-type, response-type, and PKCE-method registries.
//!
//! These three closed enums are how IronAuth structurally EXCLUDES the forbidden
//! flows (OAuth 2.1 posture, RFC 9700). The exclusion is not a disabled config
//! knob and not a runtime rejection layered on top of a broader parser: the
//! illegal states are unrepresentable, because the enums have no variant for
//! them and the parsers map every forbidden spelling to `None`.
//!
//! - [`GrantType`] has exactly one variant, [`GrantType::AuthorizationCode`].
//!   There is no `Password` variant, so the resource-owner-password-credentials
//!   (ROPC) grant has no value to match and no handler to route to: it is absent,
//!   not disabled.
//! - [`ResponseType`] is closed around a SET of exactly four members: `code`,
//!   `code id_token`, `id_token`, and `none`. There is NO component for an
//!   access token anywhere in the type, so NONE of the token-bearing response
//!   types (`token`, `code token`, `id_token token`, `code id_token token`) can
//!   be represented: the implicit access-token flow is designed OUT, not
//!   configured off. The authorization endpoint can never emit an access token,
//!   in any spelling. The three non-`code` members are legacy types disabled per
//!   environment by default (issue #17).
//! - [`PkceMethod`] has exactly one variant, [`PkceMethod::S256`]. There is no
//!   `Plain` variant, so `code_challenge_method=plain` can never be represented.
//!
//! Two further registries name the metadata sets discovery advertises (issue #18),
//! kept here so discovery sources them from the owning subsystem rather than
//! hand-listing them:
//!
//! - [`ResponseMode`] has three members: `query` (always available, the code
//!   flow's default), `fragment` (the front-channel default), and `form_post`
//!   (OAuth 2.0 Form Post Response Mode 1.0). `fragment` and `form_post` are
//!   enabled per environment alongside the legacy response types they serve
//!   (issue #17), so discovery advertises them only where enabled.
//! - [`PromptValue`] names every `prompt` value the authorization endpoint acts on
//!   (`none`, `login`, `consent`, `select_account`, `create`), and [`PromptSet`]
//!   models a parsed `prompt` request as an ORDER-INSENSITIVE SET of them (a
//!   `prompt` value is space-delimited, OIDC Core 3.1.2.1), rejecting the one
//!   illegal combination: `none` with any other value.
//!
//! A structural test (`tests/structural.rs`) enumerates each registry's full
//! variant set and asserts every forbidden spelling parses to `None`, so a future
//! edit that reintroduced a forbidden variant would fail the build.

/// The OAuth grant types IronAuth's token endpoint can service.
///
/// Closed on purpose: the members are the authorization-code grant (RFC 6749
/// 4.1.3) and the refresh-token grant (RFC 6749 6, with the RFC 9700 2.2.2 /
/// OAuth 2.1 rotation and reuse-detection rules, issue #21). ROPC (`password`),
/// the client-credentials grant, and every other grant are simply absent, so
/// there is no way to name one at this layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantType {
    /// The `authorization_code` grant (RFC 6749 4.1.3).
    AuthorizationCode,
    /// The `refresh_token` grant (RFC 6749 6, issue #21): exchanging a rotating
    /// refresh token for a fresh access token (and, per the graduated policy, a
    /// rotated refresh token).
    RefreshToken,
}

impl GrantType {
    /// Every grant type this build can express.
    pub const ALL: &'static [GrantType] = &[GrantType::AuthorizationCode, GrantType::RefreshToken];

    /// The wire `grant_type` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::RefreshToken => "refresh_token",
        }
    }

    /// Parse a wire `grant_type`. Returns `None` for every value that is not a
    /// serviced grant, so `password` (ROPC) and the rest never resolve to a
    /// handler.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "authorization_code" => Some(GrantType::AuthorizationCode),
            "refresh_token" => Some(GrantType::RefreshToken),
            _ => None,
        }
    }
}

/// The OAuth response types the authorization endpoint can service.
///
/// Closed around a SET, not a scalar: a `response_type` value is a
/// space-delimited, order-insensitive set of tokens (OAuth 2.0 Multiple Response
/// Type Encoding Practices), so `code id_token` and `id_token code` name the same
/// member. The representable members are exactly `code`, `code id_token`,
/// `id_token`, and `none`.
///
/// The dangerous legacy is designed OUT, not configured off: there is NO
/// component for an access token anywhere in this type, so NONE of the
/// token-bearing response types (`token`, `code token`, `id_token token`,
/// `code id_token token`) can be represented. The authorization endpoint can
/// therefore never emit an access token, in any spelling, by construction (the
/// permanent OAuth 2.1 / RFC 9700 2.1.2 non-goal). [`ResponseType::parse`]
/// additionally maps every token-bearing spelling to `None`, so a forbidden
/// value cannot even resolve to a handler.
///
/// `code` is always available; the other three members are legacy types DISABLED
/// per environment by default and enabled only by explicit configuration (issue
/// #17), so they appear in discovery only where enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseType {
    /// `code`: the authorization-code flow (the default, always available).
    Code,
    /// `code id_token`: the hybrid flow. The authorization endpoint returns a
    /// code AND a front-channel ID token carrying `c_hash` (never an access
    /// token, and never `at_hash`, since no token is issued here).
    CodeIdToken,
    /// `id_token`: the implicit ID-token-only flow. The authorization endpoint
    /// returns a front-channel ID token with no code and no access token (so no
    /// `c_hash` and no `at_hash`).
    IdToken,
    /// `none`: the endpoint returns no code and no token, only `state` and the
    /// RFC 9207 `iss`; used to exercise a redirect without issuing anything.
    None,
}

impl ResponseType {
    /// Every response type this build can express. Exactly these four, by
    /// design: no token-bearing member exists, so the implicit access-token flow
    /// is unrepresentable.
    pub const ALL: &'static [ResponseType] = &[
        ResponseType::Code,
        ResponseType::CodeIdToken,
        ResponseType::IdToken,
        ResponseType::None,
    ];

    /// The response types available in EVERY environment without configuration:
    /// exactly `code`. The other members are legacy types enabled per
    /// environment, so discovery advertises them only where enabled (issue #17).
    pub const DEFAULT: &'static [ResponseType] = &[ResponseType::Code];

    /// The wire `response_type` value. For the hybrid flow this is the registered
    /// `code id_token` spelling (space-separated, in that canonical order).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ResponseType::Code => "code",
            ResponseType::CodeIdToken => "code id_token",
            ResponseType::IdToken => "id_token",
            ResponseType::None => "none",
        }
    }

    /// Parse a wire `response_type` as an ORDER-INSENSITIVE SET of tokens. The
    /// only recognized components are `code` and `id_token` (plus the standalone
    /// `none`); every other token, in particular the access-token component
    /// `token`, makes the whole value unrepresentable (returns `None`), so no
    /// token-bearing response type ever resolves. Duplicates collapse (it is a
    /// set); an empty value, or `none` combined with any other token, is invalid.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let (mut code, mut id_token, mut none) = (false, false, false);
        for token in raw.split_ascii_whitespace() {
            match token {
                "code" => code = true,
                "id_token" => id_token = true,
                "none" => none = true,
                // The access-token component `token` (and anything unknown) is
                // unrepresentable: the whole set is rejected.
                _ => return None,
            }
        }
        match (code, id_token, none) {
            (true, false, false) => Some(ResponseType::Code),
            (true, true, false) => Some(ResponseType::CodeIdToken),
            (false, true, false) => Some(ResponseType::IdToken),
            (false, false, true) => Some(ResponseType::None),
            // Empty, or `none` combined with another token, is not a valid set.
            _ => None,
        }
    }

    /// Whether this response type delivers a front-channel ID token (`id_token`
    /// and `code id_token`). A front-channel type fixes the default response mode
    /// to `fragment`, forbids `query`, mints an ID token at the authorization
    /// endpoint, and therefore REQUIRES `nonce`.
    #[must_use]
    pub fn is_front_channel(self) -> bool {
        matches!(self, ResponseType::CodeIdToken | ResponseType::IdToken)
    }

    /// Whether the flow issues an authorization `code` (`code` and
    /// `code id_token`), persisted for later redemption at the token endpoint.
    #[must_use]
    pub fn issues_code(self) -> bool {
        matches!(self, ResponseType::Code | ResponseType::CodeIdToken)
    }

    /// The default response mode (OAuth 2.0 Multiple Response Type Encoding
    /// Practices): `query` for `code` and `none`, `fragment` for the
    /// front-channel types.
    #[must_use]
    pub fn default_response_mode(self) -> ResponseMode {
        if self.is_front_channel() {
            ResponseMode::Fragment
        } else {
            ResponseMode::Query
        }
    }
}

/// The PKCE code-challenge methods IronAuth accepts.
///
/// Closed on purpose: the only member is `S256`. `plain` is absent, so a downgrade
/// to plain PKCE cannot be represented at this layer. (Requiring PKCE and
/// enforcing S256-only for every client is the #13 hardening; here the method is
/// merely bound and verified when present, and `plain` is already unrepresentable.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkceMethod {
    /// `S256`: `code_challenge = BASE64URL(SHA256(code_verifier))` (RFC 7636).
    S256,
}

impl PkceMethod {
    /// Every PKCE method this build can express. Exactly one, by design.
    pub const ALL: &'static [PkceMethod] = &[PkceMethod::S256];

    /// The wire `code_challenge_method` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PkceMethod::S256 => "S256",
        }
    }

    /// Parse a wire `code_challenge_method`. Returns `None` for every value that
    /// is not `S256`, so `plain` never resolves to a method.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "S256" => Some(PkceMethod::S256),
            _ => None,
        }
    }
}

/// The OAuth response modes the authorization endpoint can return a result by.
///
/// `query` (the code flow's default) is always available. `fragment` (the
/// front-channel default) and `form_post` (OAuth 2.0 Form Post Response Mode 1.0)
/// are enabled per environment alongside the legacy response types they serve
/// (issue #17), so discovery advertises them only where enabled. The negotiator
/// forbids the one dangerous combination: a front-channel response type may never
/// use `query`, which would place an ID token in the (logged, Referer-leaked)
/// query string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode {
    /// `query`: the response parameters are in the redirect query string.
    Query,
    /// `fragment`: the response parameters are in the redirect URL fragment.
    Fragment,
    /// `form_post`: the response parameters are posted to the redirect URI by an
    /// auto-submitting HTML form, so they never appear in a URL.
    FormPost,
}

impl ResponseMode {
    /// Every response mode this build can express.
    pub const ALL: &'static [ResponseMode] = &[
        ResponseMode::Query,
        ResponseMode::Fragment,
        ResponseMode::FormPost,
    ];

    /// The response modes available in EVERY environment without configuration:
    /// exactly `query`. `fragment` and `form_post` are enabled per environment,
    /// so discovery advertises them only where enabled (issue #17).
    pub const DEFAULT: &'static [ResponseMode] = &[ResponseMode::Query];

    /// The wire / metadata `response_mode` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ResponseMode::Query => "query",
            ResponseMode::Fragment => "fragment",
            ResponseMode::FormPost => "form_post",
        }
    }

    /// Parse a wire `response_mode`. Returns `None` for every unknown value.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "query" => Some(ResponseMode::Query),
            "fragment" => Some(ResponseMode::Fragment),
            "form_post" => Some(ResponseMode::FormPost),
            _ => None,
        }
    }
}

/// The OIDC `prompt` values the authorization endpoint acts on (OIDC Core
/// 3.1.2.1, plus `create` from Initiating User Registration via OpenID Connect).
///
/// `none` renders no UI and returns the corresponding `*_required` error through
/// the negotiated response mode; `login` forces fresh authentication;
/// `select_account` forces account selection (which, under the single-session
/// bootstrap, degrades to a forced re-login); `consent` forces the consent screen;
/// `create` routes an unauthenticated user to the registration surface. A `prompt`
/// value is a SET of these (see [`PromptSet`]); the whole set drives the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptValue {
    /// `none`: render no authentication or consent UI. If interaction would be
    /// required, return the matching `*_required` error instead of a page.
    None,
    /// `login`: force fresh authentication even with a valid session.
    Login,
    /// `consent`: force the consent screen even when consent already exists.
    Consent,
    /// `select_account`: force account selection (single-session: re-login).
    SelectAccount,
    /// `create`: route an unauthenticated user to the registration surface.
    Create,
}

impl PromptValue {
    /// Every prompt value the authorization endpoint acts on, in the order
    /// discovery advertises them (`none login consent select_account create`).
    pub const ALL: &'static [PromptValue] = &[
        PromptValue::None,
        PromptValue::Login,
        PromptValue::Consent,
        PromptValue::SelectAccount,
        PromptValue::Create,
    ];

    /// The wire / metadata `prompt` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PromptValue::None => "none",
            PromptValue::Login => "login",
            PromptValue::Consent => "consent",
            PromptValue::SelectAccount => "select_account",
            PromptValue::Create => "create",
        }
    }

    /// Parse a single wire `prompt` token. Returns `None` for every value the
    /// endpoint does not act on, so an unrecognized token makes the whole set
    /// unrepresentable (see [`PromptSet::parse`]).
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "none" => Some(PromptValue::None),
            "login" => Some(PromptValue::Login),
            "consent" => Some(PromptValue::Consent),
            "select_account" => Some(PromptValue::SelectAccount),
            "create" => Some(PromptValue::Create),
            _ => None,
        }
    }
}

/// A parsed `prompt` request: an ORDER-INSENSITIVE SET of [`PromptValue`]s (OIDC
/// Core 3.1.2.1). `prompt` is space-delimited, so `login consent` and
/// `consent login` name the same set and duplicates collapse.
///
/// The one illegal combination the parser rejects is `none` with ANY other value:
/// `none` means "render no UI", which cannot coexist with a value that demands UI,
/// so the whole request is `invalid_request` (per spec). An unrecognized token also
/// makes the set unrepresentable, mirroring [`ResponseType::parse`].
// A set membership flag per `prompt` value: one field per registry member, which is
// exactly what a SET is. Folding them into a state machine or two-variant enums (the
// excessive-bools remedy) would obscure the one-to-one mapping to the wire values
// for no gain, so the lint is allowed here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PromptSet {
    none: bool,
    login: bool,
    consent: bool,
    select_account: bool,
    create: bool,
}

impl PromptSet {
    /// Parse a wire `prompt` value as an order-insensitive set of tokens.
    ///
    /// # Errors
    ///
    /// [`PromptSetError::Unknown`] if any token is not a recognized `prompt` value;
    /// [`PromptSetError::NoneWithOther`] if `none` is combined with any other value.
    pub fn parse(raw: &str) -> Result<Self, PromptSetError> {
        let mut set = PromptSet::default();
        for token in raw.split_ascii_whitespace() {
            match PromptValue::parse(token) {
                Some(PromptValue::None) => set.none = true,
                Some(PromptValue::Login) => set.login = true,
                Some(PromptValue::Consent) => set.consent = true,
                Some(PromptValue::SelectAccount) => set.select_account = true,
                Some(PromptValue::Create) => set.create = true,
                None => return Err(PromptSetError::Unknown),
            }
        }
        // `none` renders no UI, so it cannot be combined with a UI-demanding value.
        if set.none && (set.login || set.consent || set.select_account || set.create) {
            return Err(PromptSetError::NoneWithOther);
        }
        Ok(set)
    }

    /// Whether the set contains `value`.
    #[must_use]
    pub fn contains(self, value: PromptValue) -> bool {
        match value {
            PromptValue::None => self.none,
            PromptValue::Login => self.login,
            PromptValue::Consent => self.consent,
            PromptValue::SelectAccount => self.select_account,
            PromptValue::Create => self.create,
        }
    }

    /// Whether the request carried no prompt value at all.
    #[must_use]
    pub fn is_empty(self) -> bool {
        !(self.none || self.login || self.consent || self.select_account || self.create)
    }

    /// This set with `value` removed (issue #16). The interaction that SATISFIES a
    /// forcing prompt token (a login satisfies `login`/`select_account`, a consent
    /// satisfies `consent`) rebuilds the resume URL without it, so the resumed
    /// request does not re-force the same interaction and loop forever.
    #[must_use]
    pub fn without(mut self, value: PromptValue) -> Self {
        match value {
            PromptValue::None => self.none = false,
            PromptValue::Login => self.login = false,
            PromptValue::Consent => self.consent = false,
            PromptValue::SelectAccount => self.select_account = false,
            PromptValue::Create => self.create = false,
        }
        self
    }

    /// Serialize back to a space-separated `prompt` value in canonical order, or
    /// [`None`] when the set is empty (so a resume URL omits the parameter). Only
    /// ever emits recognized tokens, so a round-trip through [`Self::parse`] is
    /// stable.
    #[must_use]
    pub fn to_param(self) -> Option<String> {
        let mut out = Vec::new();
        if self.none {
            out.push("none");
        }
        if self.login {
            out.push("login");
        }
        if self.consent {
            out.push("consent");
        }
        if self.select_account {
            out.push("select_account");
        }
        if self.create {
            out.push("create");
        }
        if out.is_empty() {
            None
        } else {
            Some(out.join(" "))
        }
    }
}

/// Why a `prompt` request was rejected. Both map to `invalid_request`; neither
/// carries a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptSetError {
    /// `none` was combined with another prompt value (OIDC Core 3.1.2.1).
    NoneWithOther,
    /// The value contained a token that is not a recognized `prompt` value.
    Unknown,
}

impl PromptSetError {
    /// A short, non-secret description for the `error_description`.
    #[must_use]
    pub fn as_description(self) -> &'static str {
        match self {
            PromptSetError::NoneWithOther => {
                "prompt=none must not be combined with any other prompt value"
            }
            PromptSetError::Unknown => "the prompt parameter contains an unsupported value",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_type_registry_is_exactly_the_four_token_free_members() {
        // The structural lock (issue #17): the registry is EXACTLY these four
        // members, in this order. No token-bearing member exists, so a future edit
        // that added `token`, `code token`, `id_token token`, or
        // `code id_token token` would fail this exact-set assertion (it would have
        // to grow ALL) and the build would break.
        assert_eq!(
            ResponseType::ALL,
            &[
                ResponseType::Code,
                ResponseType::CodeIdToken,
                ResponseType::IdToken,
                ResponseType::None,
            ]
        );
        assert_eq!(ResponseType::ALL.len(), 4);
        // Every representable member decomposes into ONLY the token-free
        // components {code, id_token, none}; the access-token component `token`
        // appears in none of them, so it cannot be expressed.
        for rt in ResponseType::ALL {
            for component in rt.as_str().split(' ') {
                assert!(
                    matches!(component, "code" | "id_token" | "none"),
                    "{rt:?} decomposes into a forbidden component {component:?}"
                );
            }
            // Each member round-trips through its own wire spelling.
            assert_eq!(ResponseType::parse(rt.as_str()), Some(*rt));
        }
    }

    #[test]
    fn response_type_parses_as_an_order_insensitive_set() {
        assert_eq!(ResponseType::parse("code"), Some(ResponseType::Code));
        assert_eq!(ResponseType::parse("id_token"), Some(ResponseType::IdToken));
        assert_eq!(ResponseType::parse("none"), Some(ResponseType::None));
        // A set: order does not matter, and duplicates collapse.
        assert_eq!(
            ResponseType::parse("code id_token"),
            Some(ResponseType::CodeIdToken)
        );
        assert_eq!(
            ResponseType::parse("id_token code"),
            Some(ResponseType::CodeIdToken),
            "response_type is an order-insensitive set"
        );
        assert_eq!(
            ResponseType::parse("code   id_token"),
            Some(ResponseType::CodeIdToken),
            "extra internal whitespace is tolerated"
        );
        assert_eq!(
            ResponseType::parse("code code"),
            Some(ResponseType::Code),
            "a duplicated component collapses (it is a set)"
        );
    }

    #[test]
    fn every_token_bearing_or_invalid_spelling_is_unrepresentable() {
        // The access-token flow, in every spelling and order, parses to None: it
        // has no variant and never resolves to a handler.
        for forbidden in [
            "token",
            "code token",
            "token code",
            "id_token token",
            "token id_token",
            "code id_token token",
            "token code id_token",
            // none does not combine with any other token.
            "none code",
            "code none",
            "none id_token",
            // empty / whitespace-only is not a valid set.
            "",
            "   ",
            // unknown members.
            "unknown",
            "code unknown",
        ] {
            assert!(
                ResponseType::parse(forbidden).is_none(),
                "response_type {forbidden:?} must be unrepresentable"
            );
        }
    }

    #[test]
    fn response_type_front_channel_and_code_predicates() {
        // code: a code, not front-channel.
        assert!(ResponseType::Code.issues_code());
        assert!(!ResponseType::Code.is_front_channel());
        // code id_token: both a code and a front-channel ID token.
        assert!(ResponseType::CodeIdToken.issues_code());
        assert!(ResponseType::CodeIdToken.is_front_channel());
        // id_token: a front-channel ID token, no code.
        assert!(!ResponseType::IdToken.issues_code());
        assert!(ResponseType::IdToken.is_front_channel());
        // none: neither.
        assert!(!ResponseType::None.issues_code());
        assert!(!ResponseType::None.is_front_channel());
    }

    #[test]
    fn default_response_modes_match_the_spec() {
        // OAuth 2.0 Multiple Response Type Encoding Practices: query for code and
        // none, fragment for the front-channel types.
        assert_eq!(
            ResponseType::Code.default_response_mode(),
            ResponseMode::Query
        );
        assert_eq!(
            ResponseType::None.default_response_mode(),
            ResponseMode::Query
        );
        assert_eq!(
            ResponseType::IdToken.default_response_mode(),
            ResponseMode::Fragment
        );
        assert_eq!(
            ResponseType::CodeIdToken.default_response_mode(),
            ResponseMode::Fragment
        );
    }

    #[test]
    fn prompt_value_registry_is_exactly_the_five_acted_on_values() {
        // The structural lock (issue #16): every value the endpoint acts on, in the
        // order discovery advertises them. `create` is included so the registration
        // deep-link stays advertised.
        assert_eq!(
            PromptValue::ALL,
            &[
                PromptValue::None,
                PromptValue::Login,
                PromptValue::Consent,
                PromptValue::SelectAccount,
                PromptValue::Create,
            ]
        );
        assert!(PromptValue::ALL.contains(&PromptValue::Create));
        for value in PromptValue::ALL {
            assert_eq!(PromptValue::parse(value.as_str()), Some(*value));
        }
    }

    #[test]
    fn prompt_set_parses_as_an_order_insensitive_set() {
        let single = PromptSet::parse("login").expect("valid");
        assert!(single.contains(PromptValue::Login));
        assert!(!single.contains(PromptValue::Consent));
        assert!(!single.is_empty());

        // Order does not matter and duplicates collapse.
        let a = PromptSet::parse("login consent").expect("valid");
        let b = PromptSet::parse("consent   login").expect("valid");
        let c = PromptSet::parse("login login consent").expect("valid");
        assert_eq!(a, b, "prompt is an order-insensitive set");
        assert_eq!(a, c, "a duplicated value collapses");
        assert!(a.contains(PromptValue::Login) && a.contains(PromptValue::Consent));

        // An empty/whitespace value is the empty set (no prompt requested).
        assert!(PromptSet::parse("   ").expect("valid").is_empty());
    }

    #[test]
    fn prompt_none_is_rejected_when_combined_and_unknown_tokens_are_rejected() {
        // `none` alone is fine.
        assert!(
            PromptSet::parse("none")
                .expect("valid")
                .contains(PromptValue::None)
        );
        // `none` with ANY other value is invalid_request (OIDC Core 3.1.2.1).
        for combined in ["none login", "login none", "none consent", "none create"] {
            assert_eq!(
                PromptSet::parse(combined),
                Err(PromptSetError::NoneWithOther),
                "{combined:?} must be rejected"
            );
        }
        // An unrecognized token makes the whole set unrepresentable.
        for unknown in ["nope", "login foobar", "select-account"] {
            assert_eq!(
                PromptSet::parse(unknown),
                Err(PromptSetError::Unknown),
                "{unknown:?} must be rejected"
            );
        }
    }

    #[test]
    fn response_mode_registry_and_parsing() {
        assert_eq!(
            ResponseMode::ALL,
            &[
                ResponseMode::Query,
                ResponseMode::Fragment,
                ResponseMode::FormPost,
            ]
        );
        assert_eq!(ResponseMode::DEFAULT, &[ResponseMode::Query]);
        for mode in ResponseMode::ALL {
            assert_eq!(ResponseMode::parse(mode.as_str()), Some(*mode));
        }
        // Unknown modes (including the JARM `jwt`, deferred to M16) do not resolve.
        for unknown in ["", "jwt", "web_message", "Query"] {
            assert!(ResponseMode::parse(unknown).is_none(), "{unknown:?}");
        }
    }
}
