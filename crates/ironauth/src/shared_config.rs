// SPDX-License-Identifier: MIT OR Apache-2.0

//! The values BOTH planes must receive identically (issue #414).
//!
//! Some of what the boot path resolves is consumed on BOTH the OIDC data plane and the
//! management plane: the mint enforces a bound and the management API reports against
//! the same bound, the login path records connector health and the admin diagnostics
//! read reports it, the mint stamps an `iss` the console credential bridge enforces.
//! That is why `[organizations]` and `[token_claims]` are top-level sections rather
//! than fields on `[oidc]` or `[admin]`: one setting, one operator-visible name.
//!
//! Before this module each of those was resolved separately per plane, from separate
//! parameters, which made three silent failures expressible for every one of them:
//! dropping the install on the management plane, dropping it on the data plane, and
//! handing the two planes DIFFERENT values. Measured on `[token_claims]`: dropping the
//! management-plane install and giving the two planes different sections each built
//! with ZERO warnings, and dropping the data-plane install was caught only
//! incidentally, by `unused_variable`.
//!
//! This module makes all three UNREPRESENTABLE rather than merely detectable:
//!
//!   * every cross-plane value is declared ONCE, in the [`shared_plane_inputs!`]
//!     invocation below, which generates the carrier struct, its capture constructor,
//!     the per-plane install trait, the single install body and the name lists;
//!   * a plane implements [`SharedPlaneState`] in FULL or the crate does not compile,
//!     so a newly declared value cannot be installed on one plane and forgotten on the
//!     other;
//!   * [`SharedPlaneInputs`] has private fields and exactly one constructor,
//!     [`SharedPlaneInputs::capture`], which takes the loaded `Config`, the feature
//!     registry and the environment seam and resolves EVERY declared value from them.
//!     Nothing is passed in already resolved, so the boot path holds one carrier and
//!     hands it to both planes. There is no second value a plane could be handed, and
//!     no positional argument at the capture site that could be filled from the wrong
//!     source;
//!   * [`SharedPlaneInputs::install`] is generic over the plane, so both planes run the
//!     SAME install body over the SAME captured values.
//!
//! Four kinds of value are declared, because they arrive differently, are consumed
//! differently and are proved differently:
//!
//!   * `from_config` values are whole config SECTIONS, cloned out of the loaded
//!     `Config` and INSTALLED on each plane state by a builder. They are what the
//!     whole-of-`Config` classification check measures against, so a section added to
//!     `Config` cannot escape this discipline unnoticed;
//!   * `from_boot` values are INSTALLED too, but are resolved rather than read: the
//!     strict feature-ladder verdicts, which are never a plain config toggle;
//!   * `shared_objects` are INSTALLED runtime objects where equality is not enough,
//!     because one plane writes into the object and the other reads out of it. Both
//!     planes must hold the SAME `Arc`, and the harness requires an object-identity
//!     probe for exactly the names declared here;
//!   * `derived_values` and `derived_objects` are NOT installed by a builder at all.
//!     They are CONSTRUCTOR inputs (the issuer base, the JWKS cache window, the
//!     envelope master key), each a pure derivation from the one `Config`, each carried
//!     here so that neither plane can be handed a second derivation. `derived_objects`
//!     additionally demands an identity probe, for the same reason `shared_objects`
//!     does.
//!
//! What is still expressible, and therefore what the boot-wiring harness in
//! `boot_wiring_tests` drives against the REAL `assemble_planes`:
//!
//!   * a [`SharedPlaneState`] method that compiles but installs nothing (the
//!     management plane's builders write through `Arc::get_mut`, which SILENTLY
//!     no-ops once the state is shared, so a stub is not hypothetical);
//!   * a boot path that stops calling [`SharedPlaneInputs::install`] for one plane;
//!   * a plane assembled from a SECOND carrier rather than the one the boot path
//!     captured;
//!   * a constructor input taken from somewhere other than this carrier.
//!
//! What the two structural checks in this file cover, stated exactly, because the
//! honest scope of a guard is the guard:
//!
//!   * `every_config_key_is_either_a_declared_shared_section_or_classified_plane_local`
//!     covers the CONFIG-SOURCED half. Its universe is the serialized shape of `Config`
//!     itself, so a SECTION added to `Config` and threaded to both planes by hand turns
//!     it red;
//!   * `the_builders_both_plane_states_offer_are_exactly_the_declared_shared_values`
//!     covers the BOOT-SOURCED half, which `Config` cannot see. Its universe is the
//!     `with_*` builders the two plane states actually offer, read out of their source,
//!     and the rule is that a builder BOTH states offer is a cross-plane value and must
//!     be declared here. A boot-resolved value threaded to both planes by hand needs a
//!     builder on both states, so it turns that check red;
//!   * neither check sees a cross-plane value that reaches the two planes through
//!     builders with DIFFERENT names on each state, or through a constructor argument
//!     that is not declared in `derived_values` or `derived_objects`. Those two shapes
//!     are the remaining gap, and nothing here would notice them.

use std::sync::Arc;

use ironauth_admin::AdminState;
use ironauth_config::{
    ADVANCED_RECOVERY_FEATURE, Config, FeatureRegistry, OrganizationsConfig,
    SIGNUP_QUARANTINE_FEATURE, TokenClaimsConfig,
};
use ironauth_env::Env;
use ironauth_jose::MasterKey;
use ironauth_oidc::{FederationRuntime, JwksCacheWindow, LazyMigrationHook, OidcState};
use ironauth_server::{ServerError, SiteContext};

/// How the boot path builds an outbound fetcher, and the ONE place tests differ (issue #674).
///
/// Production reads the OS trust store, which is right: an outbound fetcher that trusts
/// nothing would fail every https handshake, and failing at startup beats failing at first
/// use.
///
/// The WIRING tests must not. They assert that a value the config declares reaches both
/// planes, and coupling that to the host keychain made them report a TLS failure as "the
/// plane does not hold the configured value", which names neither the cause nor the file it
/// is in. When the trust-settings API on this machine began refusing, that is exactly what
/// happened and it took a bisect to see it was not a code change.
#[cfg(not(test))]
pub(crate) fn outbound_fetcher(
    limits: ironauth_fetch::FetchLimits,
) -> Result<ironauth_fetch::Fetcher, ironauth_fetch::TlsSetupError> {
    ironauth_fetch::Fetcher::new(limits)
}

/// The hermetic counterpart. See [`outbound_fetcher`].
///
/// The `Result` is never `Err` and must stay: this has to be substitutable for the production
/// signature, and a version that could not fail would let a caller stop handling the failure
/// that production still has.
#[cfg(test)]
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn outbound_fetcher(
    limits: ironauth_fetch::FetchLimits,
) -> Result<ironauth_fetch::Fetcher, ironauth_fetch::TlsSetupError> {
    Ok(ironauth_fetch::Fetcher::for_tests(limits))
}

/// Everything [`SharedPlaneInputs::capture`] resolves the declared values FROM.
///
/// One struct rather than a positional argument list, so a declaration's resolver names
/// the source it reads (`source.features`, `source.config`) instead of receiving it in
/// a position that could be filled from the wrong place. Nothing already resolved is
/// passed in: the capture site hands over the loaded config, the feature registry and
/// the environment seam, and every declared value below is derived from those three.
pub struct CaptureSource<'a> {
    /// The ONE loaded, strictly validated config.
    config: &'a Config,
    /// The strict feature-maturity ladder, already validated by the boot path.
    features: &'a FeatureRegistry,
    /// The clock and entropy seam the shared runtime objects read through.
    env: &'a Env,
}

/// Declare the cross-plane values ONCE.
///
/// Each entry names the value, its type, how it is resolved from a [`CaptureSource`],
/// and (for the installed kinds) both the per-plane install method the trait requires
/// and the state builder `via` which that install must reach the plane. From those
/// lists this generates:
///
///   * `struct SharedPlaneInputs`, one private field per value;
///   * `SharedPlaneInputs::capture`, the ONLY constructor;
///   * `trait SharedPlaneState`, one required method per INSTALLED value, so a plane
///     that does not install every one of them fails to compile;
///   * `SharedPlaneInputs::install`, the single generic install body both planes run;
///   * an accessor per DERIVED value, which is how a plane's constructor reads it;
///   * the name lists the boot-wiring harness derives its subject list from, and the
///     `(install method, builder)` pairs the both-planes builder census is measured
///     against.
///
/// Adding a value here is the whole change: both planes then must receive it, both
/// receive the same captured value, and the harness gains a required subject.
macro_rules! shared_plane_inputs {
    (
        from_config {
            $($section:ident : $section_ty:ty
                => $section_install:ident via $section_builder:ident),+ $(,)?
        }
        from_boot {
            $($input:ident : $input_ty:ty = $input_resolve:expr
                => $input_install:ident via $input_builder:ident),+ $(,)?
        }
        shared_objects {
            $($object:ident : $object_ty:ty = $object_resolve:expr
                => $object_install:ident via $object_builder:ident),+ $(,)?
        }
        derived_values {
            $($value:ident : $value_ty:ty = $value_resolve:expr),+ $(,)?
        }
        derived_objects {
            $($shared:ident : $shared_ty:ty = $shared_resolve:expr),+ $(,)?
        }
    ) => {
        /// The values captured ONCE at boot and given to BOTH planes.
        ///
        /// Fields are private and the only constructor is
        /// [`SharedPlaneInputs::capture`], so the boot path holds one carrier and both
        /// planes take every cross-plane value from it. That is what makes cross-plane
        /// divergence unrepresentable rather than merely tested: there is no second
        /// value to hand a plane.
        ///
        /// Deliberately NOT `Clone`: a clone would be a second carrier, and the whole
        /// point of the type is that exactly one exists per boot.
        #[derive(Debug)]
        pub struct SharedPlaneInputs {
            $($section: $section_ty,)+
            $($input: $input_ty,)+
            $($object: $object_ty,)+
            $($value: $value_ty,)+
            $($shared: $shared_ty,)+
        }

        impl SharedPlaneInputs {
            /// Capture every cross-plane value, ONCE, from the one loaded config.
            ///
            /// Called once on the boot path, before `config` moves into the server.
            /// Every declared value is resolved HERE, from `config`, the validated
            /// feature ladder and the environment seam. Nothing arrives already
            /// resolved, so there is no argument at this call site that could be filled
            /// in from the wrong source.
            ///
            /// # Errors
            ///
            /// [`ServerError::InvalidPublicUrl`] if `server.public_url` is set but is
            /// not a valid `http`/`https` base URL. The boot then refuses, exactly as
            /// `Server::new` would, only earlier and before any store is opened.
            pub fn capture(
                config: &Config,
                features: &FeatureRegistry,
                env: &Env,
            ) -> Result<Self, ServerError> {
                let source = CaptureSource { config, features, env };
                Ok(Self {
                    $($section: source.config.$section.clone(),)+
                    $($input: ($input_resolve)(&source)?,)+
                    $($object: ($object_resolve)(&source)?,)+
                    $($value: ($value_resolve)(&source)?,)+
                    $($shared: ($shared_resolve)(&source)?,)+
                })
            }

            /// Install every INSTALLED cross-plane value on one plane.
            ///
            /// Generic over the plane, so the OIDC data plane and the management plane
            /// run this SAME body over the SAME captured values. There is deliberately
            /// no per-value entry point: a caller cannot install a subset.
            ///
            /// The DERIVED values are not installed here because no plane has a builder
            /// for them: they are constructor inputs, read off this carrier through the
            /// generated accessors at the point each plane is constructed.
            #[must_use]
            pub fn install<S: SharedPlaneState>(&self, state: S) -> S {
                $(let state = state.$section_install(&self.$section);)+
                $(let state = state.$input_install(&self.$input);)+
                $(let state = state.$object_install(&self.$object);)+
                state
            }

            $(
                #[doc = concat!(
                    "The captured `",
                    stringify!($value),
                    "`, a pure derivation from the one loaded config. Both planes take \
                     it from HERE rather than deriving their own, so there is no second \
                     derivation to disagree.",
                )]
                #[must_use]
                pub fn $value(&self) -> &$value_ty {
                    &self.$value
                }
            )+

            $(
                #[doc = concat!(
                    "The captured `",
                    stringify!($shared),
                    "`. Both planes take THIS object rather than resolving their own, \
                     so they hold the same one and not merely an equal one.",
                )]
                #[must_use]
                pub fn $shared(&self) -> &$shared_ty {
                    &self.$shared
                }
            )+
        }

        /// A plane that receives the cross-plane values.
        ///
        /// Every method is required, so declaring a new installed value in
        /// [`shared_plane_inputs!`] breaks the build of any plane that has not
        /// installed it. That is the guard against a value reaching one plane only.
        pub trait SharedPlaneState: Sized {
            $(
                /// Install this shared config section on the plane.
                #[must_use]
                fn $section_install(self, section: &$section_ty) -> Self;
            )+
            $(
                /// Install this shared boot-resolved value on the plane.
                #[must_use]
                fn $input_install(self, input: &$input_ty) -> Self;
            )+
            $(
                /// Install this shared runtime object on the plane. Both planes must end
                /// up holding the SAME object, not merely equal configuration.
                #[must_use]
                fn $object_install(self, object: &$object_ty) -> Self;
            )+
        }

        /// Every shared config SECTION's key, in declaration order.
        ///
        /// The source of truth the harness derives its subject list from, and the list
        /// the whole-of-`Config` classification check measures against, so a section
        /// declared above cannot be silently left undriven. Test-only because the boot
        /// path consumes the DECLARATION (the trait and the install body), not its
        /// names; this is the same declaration reflected as strings, generated by the
        /// same macro expansion, so it cannot drift from what the boot path installs.
        #[cfg(test)]
        pub const SHARED_CONFIG_SECTION_NAMES: &[&str] = &[$(stringify!($section),)+];

        /// Every shared value the boot path RESOLVES rather than reads as a section, in
        /// declaration order: the ladder verdicts, the shared runtime objects and the
        /// derived constructor inputs. Test-only, for the same reason as
        /// [`SHARED_CONFIG_SECTION_NAMES`].
        #[cfg(test)]
        pub const SHARED_BOOT_INPUT_NAMES: &[&str] = &[
            $(stringify!($input),)+
            $(stringify!($object),)+
            $(stringify!($value),)+
            $(stringify!($shared),)+
        ];

        /// Every shared value whose contract is OBJECT IDENTITY, in declaration order.
        ///
        /// This is why the object kinds are declared apart: for these the contract is
        /// that both planes hold the SAME object, because one plane writes into it and
        /// the other reads out of it, or because the value cannot be compared any other
        /// way without exposing key material. Equality of configuration would satisfy an
        /// ordinary probe and still be wrong, so the harness REQUIRES an identity probe
        /// for exactly the names in this list. Declaring a new one therefore demands
        /// that probe rather than merely inviting it.
        #[cfg(test)]
        pub const SHARED_OBJECT_NAMES: &[&str] =
            &[$(stringify!($object),)+ $(stringify!($shared),)+];

        /// Every value that is a plane CONSTRUCTOR input rather than a builder install,
        /// in declaration order. The harness uses it to hold each probe to the right
        /// non-vacuity evidence.
        #[cfg(test)]
        pub const SHARED_DERIVED_NAMES: &[&str] =
            &[$(stringify!($value),)+ $(stringify!($shared),)+];

        /// Every INSTALLED value's `(install method, plane-state builder)` pair, in
        /// declaration order.
        ///
        /// The `via` half is what the both-planes builder census is measured against: a
        /// builder that BOTH plane states offer and that is not in this list is an
        /// undeclared cross-plane value. Test-only, and checked against the install
        /// bodies themselves so the `via` name cannot be a claim the code does not keep.
        #[cfg(test)]
        pub const SHARED_PLANE_BUILDERS: &[(&str, &str)] = &[
            $((stringify!($section_install), stringify!($section_builder)),)+
            $((stringify!($input_install), stringify!($input_builder)),)+
            $((stringify!($object_install), stringify!($object_builder)),)+
        ];
    };
}

shared_plane_inputs! {
    from_config {
        // The organization group nesting bound (issue #97): the management API enforces
        // it at write time and the mint-path effective-role resolution uses it as the
        // hard termination guard on the ancestor walk.
        organizations: OrganizationsConfig
            => install_organizations via with_max_group_depth,
        // The token claim budget (issue #98): the mint enforces it and the management
        // API reports the approach warning against it.
        token_claims: TokenClaimsConfig
            => install_token_claims via with_token_claims,
    }
    from_boot {
        // The experimental signup fraud review queue (issue #82, PR 2), resolved
        // through the strict feature ladder: the data plane quarantines and the
        // management plane serves the review queue, so a plane that disagreed would
        // either quarantine with no way to review or expose a queue nothing fills.
        // Resolved HERE, where the feature is named exactly once, so no call site can
        // supply this verdict out of the other feature's ladder entry.
        signup_quarantine_enabled: bool = |source: &CaptureSource<'_>| {
            Ok(source
                .features
                .is_enabled(source.config, SIGNUP_QUARANTINE_FEATURE))
        } => install_signup_quarantine_enabled via with_signup_quarantine_enabled,
        // The experimental admin-approved recovery review queue (issue #82, PR 3), for
        // the same reason and resolved the same way.
        advanced_recovery_enabled: bool = |source: &CaptureSource<'_>| {
            Ok(source
                .features
                .is_enabled(source.config, ADVANCED_RECOVERY_FEATURE))
        } => install_advanced_recovery_enabled via with_advanced_recovery_enabled,
    }
    shared_objects {
        // The inbound lazy-migration hook (issue #56): the login path drives the
        // circuit breaker INSIDE this object and the management plane's
        // migration-progress endpoint reports THIS node's breaker state out of it, so
        // the two planes must hold the SAME `Arc` and not merely equal configuration.
        // Built only when the OIDC provider is mounted (the login path it guards) AND
        // the hook is enabled; disabled or misconfigured yields `None`, and the login
        // path is then unchanged.
        migration_hook: Option<Arc<LazyMigrationHook>> = |source: &CaptureSource<'_>| {
            Ok(if source.config.oidc.enabled {
                ironauth_oidc::build_lazy_migration_hook_with(
                    &source.config.oidc.lazy_migration,
                    source.env,
                    outbound_fetcher,
                )
            } else {
                None
            })
        } => install_migration_hook via with_migration_hook,
        // The OIDC upstream federation runtime (issue #75) and its per-connector health
        // registry (issue #76): the login legs record health INTO the registry the
        // admin health-diagnostics read reports OUT of, so again the SAME `Arc`. Built
        // only when OIDC is mounted and federation is enabled; otherwise `None`.
        federation_runtime: Option<Arc<FederationRuntime>> = |source: &CaptureSource<'_>| {
            Ok(if source.config.oidc.enabled {
                crate::build_federation_runtime_with(&source.config.oidc, || {
                    outbound_fetcher(ironauth_fetch::FetchLimits::default())
                })
            } else {
                None
            })
        } => install_federation_runtime via with_federation,
    }
    derived_values {
        // The public issuer root, derived ONCE. It decides what the mint stamps as
        // `iss`, what the published JWKS and discovery are served under, and what the
        // console credential bridge on the MANAGEMENT plane enforces `iss` against, so
        // a second derivation that disagreed would fail every console login while the
        // data plane looked healthy. This boot path used to derive it THREE times.
        // `Server::new` still runs this same pure derivation over this same
        // `config.server` for its own routing, which is the server crate's business;
        // taking the planes' value from here changes nothing about what is served and
        // leaves ONE derivation feeding both planes.
        issuer_base: String = |source: &CaptureSource<'_>| {
            SiteContext::derive(&source.config.server).map(|site| site.base_url())
        },
        // The JWKS and discovery cache window, clamped ONCE. Both planes' issuer
        // registries carry it (the data plane serves `Cache-Control: max-age` from it,
        // the management plane's registry caches the keys the console bridge and the
        // compatibility wizard read), so one operator-visible key stays one value.
        jwks_cache: JwksCacheWindow = |source: &CaptureSource<'_>| {
            Ok(JwksCacheWindow::clamped(
                source.config.oidc.jwks_cache_max_age_secs,
            ))
        },
    }
    derived_objects {
        // The platform envelope master key (issue #48), resolved ONCE. Every store this
        // boot path opens on either plane carries this SAME key, so the sealed PII one
        // plane writes is the sealed PII the other opens by construction rather than by
        // coincidence. Resolving it per call site also meant an operator who had not set
        // one met the same warning four times. The key redacts itself and exposes no
        // bytes, so the handle is what a test can observe.
        master_key: Option<Arc<MasterKey>> = |source: &CaptureSource<'_>| {
            Ok(crate::resolve_master_key(source.config))
        },
    }
}

impl SharedPlaneState for OidcState {
    fn install_organizations(self, section: &OrganizationsConfig) -> Self {
        self.with_max_group_depth(section.max_group_depth)
    }

    fn install_token_claims(self, section: &TokenClaimsConfig) -> Self {
        self.with_token_claims(section)
    }

    fn install_signup_quarantine_enabled(self, input: &bool) -> Self {
        self.with_signup_quarantine_enabled(*input)
    }

    fn install_advanced_recovery_enabled(self, input: &bool) -> Self {
        self.with_advanced_recovery_enabled(*input)
    }

    fn install_migration_hook(self, input: &Option<Arc<LazyMigrationHook>>) -> Self {
        // Without a hook an unknown-identifier login is the uniform failure, which is
        // the unchanged login path.
        match input {
            Some(hook) => self.with_migration_hook(Arc::clone(hook)),
            None => self,
        }
    }

    fn install_federation_runtime(self, input: &Option<Arc<FederationRuntime>>) -> Self {
        match input {
            Some(runtime) => {
                let state = self.with_federation(Arc::clone(runtime));
                tracing::info!(
                    "inbound OIDC federation wired (issue #75); the /federation routes are live \
                     for stored connectors, over a dedicated SSRF-hardened fetcher"
                );
                state
            }
            // OFF by default, so a deployment that has not enabled federation leaves the
            // `/federation` routes a uniform not-found.
            None => self,
        }
    }
}

impl SharedPlaneState for AdminState {
    fn install_organizations(self, section: &OrganizationsConfig) -> Self {
        self.with_max_group_depth(section.max_group_depth)
    }

    fn install_token_claims(self, section: &TokenClaimsConfig) -> Self {
        self.with_token_claims(section)
    }

    fn install_signup_quarantine_enabled(self, input: &bool) -> Self {
        self.with_signup_quarantine_enabled(*input)
    }

    fn install_advanced_recovery_enabled(self, input: &bool) -> Self {
        self.with_advanced_recovery_enabled(*input)
    }

    fn install_migration_hook(self, input: &Option<Arc<LazyMigrationHook>>) -> Self {
        // With no hook installed the progress endpoint reports the DB counts and no
        // breaker block.
        match input {
            Some(hook) => self.with_migration_hook(Arc::clone(hook)),
            None => self,
        }
    }

    fn install_federation_runtime(self, input: &Option<Arc<FederationRuntime>>) -> Self {
        match input {
            Some(runtime) => self.with_federation(Arc::clone(runtime)),
            None => self,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{SHARED_CONFIG_SECTION_NAMES, SHARED_PLANE_BUILDERS};

    /// This file's own source, so each declaration's `via` builder can be checked
    /// against the install body it claims to describe rather than trusted.
    const THIS_SOURCE: &str = include_str!("shared_config.rs");
    /// The boot path's own source. Kept as an ANCHOR for the whole-tree scan below
    /// (see [`crate_sources`]), which must find at least this file and its contents.
    const BOOT_SOURCE: &str = include_str!("main.rs");
    /// The management plane's state, for the both-planes builder census.
    const ADMIN_STATE_SOURCE: &str = include_str!("../../ironauth-admin/src/state.rs");
    /// The OIDC data plane's state, for the same census.
    const OIDC_STATE_SOURCE: &str = include_str!("../../ironauth-oidc/src/state.rs");

    /// How far a top-level `Config` key reaches, for the keys that are not declared
    /// cross-plane values.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Reach {
        /// Consumed by ONE plane, or by neither plane but by the server, the telemetry
        /// initializer or the store layer. The stated reason is prose a reader
        /// verifies; nothing here measures it.
        OnePlaneOrNoState,
        /// Read by NO boot path at all, on either plane: inert config. That is a claim
        /// ABOUT this crate's source, so
        /// [`no_key_classified_unread_is_read_by_the_boot_path`] measures it rather
        /// than trusting the prose.
        ///
        /// `config_type` is the name of the section's TYPE in `ironauth_config`, and it
        /// is required rather than optional because the accessor scan alone does not
        /// close the hole. Measured: with only a `.key` scan, a real read written as a
        /// struct-destructuring bind of the section out of `Config` survives, and so
        /// does one through a function parameter typed as the section's own type. A
        /// section cannot reach a boot path without its type being NAMED, so the type
        /// name is the second half of the check and between them there is no shape left.
        ///
        /// This file may name each declared type exactly ONCE, in the declaration
        /// below, which the check counts rather than exempts.
        UnreadAtBoot { config_type: &'static str },
    }

    /// Every top-level `Config` key the boot path does NOT install on BOTH plane
    /// states, each with how far it reaches and the reason.
    ///
    /// This list plus [`SHARED_CONFIG_SECTION_NAMES`] must cover the WHOLE of `Config`,
    /// and the universe is taken from `Config` itself rather than from a list written
    /// here, so a section added to `Config` and threaded to both planes by hand turns
    /// this red instead of quietly escaping the shared-value discipline. That is the
    /// rot this file exists to prevent: a subject list that stops covering things.
    ///
    /// Classifying a new key is a one line decision, and it is a decision an author
    /// must state rather than one they can omit.
    const PLANE_LOCAL_KEYS: &[(&str, Reach, &str)] = &[
        (
            "scim",
            Reach::OnePlaneOrNoState,
            "read once by `build_scim_plane` (issue #135) to size the SCIM surface's page \
             and scan bounds and to decide whether it mounts at all. ONE plane holds it: the \
             SCIM state on the public plane. The management plane never sees it, and there is \
             deliberately no `scim.uniqueness` key -- the identifier-uniqueness mode SCIM \
             needs is a SHARED value, taken from `[identifiers]` through the single \
             `uniqueness_mode` match, because two identity doors handed different modes by \
             configuration would disagree about what the same person is.",
        ),
        (
            "messaging",
            Reach::OnePlaneOrNoState,
            "consumed once at boot to build the message delivery consumer (issue #111), a \
             background task that answers no request. Neither plane's state holds it: the \
             providers become a worker's failover list and nothing serves a response from \
             them.",
        ),
        (
            "log_streams",
            Reach::OnePlaneOrNoState,
            "consumed once at boot to build the SIEM log stream shipper (issue #110), a \
             background task that answers no request. Neither plane state holds it: the \
             shipper reads audit rows and writes only a stream's cursor and health \
             columns, and handing the section to a plane would suggest a request path \
             can ship, which none does.",
        ),
        (
            "audit_retention",
            Reach::OnePlaneOrNoState,
            "consumed once at boot to build the audit retention sweeper (issue #109), a \
             background task that owns its own two connections and answers no request. \
             Neither plane state holds it: it deliberately runs on the retention role, \
             which is the one role granted DELETE on the audit tables and granted INSERT \
             on nothing, so handing it to a plane would widen exactly the credential \
             migration 0136 exists to keep narrow.",
        ),
        (
            "dev_mode",
            Reach::OnePlaneOrNoState,
            "a scalar, not a section: it relaxes the literal-secret warning at load and \
             permits the control-DSN fallback. Neither plane state holds it.",
        ),
        (
            "server",
            Reach::OnePlaneOrNoState,
            "consumed by the server crate. It DOES decide one cross-plane value, the \
             issuer base, and that value is declared here in derived_values: the boot \
             path derives it ONCE inside the capture and both planes read it off the \
             carrier, so the section itself reaches no plane state.",
        ),
        (
            "proxy",
            Reach::OnePlaneOrNoState,
            "consumed by the server crate (ProxyPolicy::from_config). Neither plane \
             state holds it.",
        ),
        (
            "telemetry",
            Reach::OnePlaneOrNoState,
            "consumed once at boot to initialize tracing, before either plane exists.",
        ),
        (
            "database",
            Reach::OnePlaneOrNoState,
            "the DSNs and the envelope master key. Both planes open stores from it, and \
             the master key both stores carry IS declared here in derived_objects; the \
             DSNs name which store to open rather than what to install, and a Store is a \
             connection handle rather than a config section on a state.",
        ),
        (
            "admin",
            Reach::OnePlaneOrNoState,
            "management plane only: AdminState::new takes it. The OIDC state never sees \
             it.",
        ),
        (
            "oidc",
            Reach::OnePlaneOrNoState,
            "data plane only: OidcState::new takes it. The management plane reads two \
             keys out of it and installs no part of it: `enabled`, as the precondition \
             for arming the console credential bridge, and `jwks_cache_max_age_secs`, \
             which is declared here in derived_values and clamped ONCE into the one \
             window both planes' issuer registries carry.",
        ),
        (
            "flows",
            Reach::OnePlaneOrNoState,
            "resolved to one boolean the boot path installs on the OIDC state only.",
        ),
        (
            "diagnostics",
            Reach::OnePlaneOrNoState,
            "installed on the OIDC state only (with_diagnostics). The management plane \
             reads diagnostics from the store, not from this section.",
        ),
        (
            "hosted_pages",
            Reach::OnePlaneOrNoState,
            "resolved to one boolean the boot path installs on the OIDC state only.",
        ),
        (
            "admin_spa",
            Reach::OnePlaneOrNoState,
            "the console runtime config and the console OIDC credential bridge: the SPA \
             router and the management plane. The OIDC state never sees it.",
        ),
        (
            "identifiers",
            Reach::OnePlaneOrNoState,
            "management plane only: the boot path installs it with \
             `AdminState::with_identifiers`, and the identifier management surface passes \
             the resolved mode to every write. RECLASSIFIED from UnreadAtBoot by epic \
             #514, which resolved the identifiers half of issue #459 by wiring the section \
             up (its option 1) rather than removing or rejecting it. It reaches ONE plane \
             because the management surface is the only production writer of \
             `user_identifiers`; a data-plane writer would move it into the shared \
             carrier, since two planes writing under different modes would corrupt the \
             uniqueness discriminator the partial index enforces.",
        ),
        (
            "quota",
            Reach::OnePlaneOrNoState,
            "seeds the one QuotaEnforcer the boot path installs on the OIDC state only.",
        ),
        (
            "password_hashing",
            Reach::OnePlaneOrNoState,
            "sizes the Argon2id pool the boot path installs on the OIDC state only.",
        ),
        (
            "password_policy",
            Reach::OnePlaneOrNoState,
            "builds the policy and the screening provider the boot path installs on the \
             OIDC state only.",
        ),
        (
            "byok",
            Reach::UnreadAtBoot {
                config_type: "ByokConfig",
            },
            "inert: no boot path INSTALLS it into either plane's state. Still tracked as \
             issue #459, whose identifiers half was wired by #519. The one read that \
             now exists is a refusal, not an installation: `Config::validate` REFUSES \
             to boot when any field here is set away from its default, so the section \
             being unconsumed can no longer be mistaken for it being configured. That \
             is the general treatment for a section that ships ahead of its consumer.",
        ),
        (
            "outbox",
            Reach::OnePlaneOrNoState,
            "the transactional outbox and job queue tuning (issue #104). RECLASSIFIED in \
             PR 2, which is the reader PR 1's UnreadAtBoot entry named in advance: the boot \
             path reads this section in outbox_worker_settings, which is the only place \
             that maps it however many consumers are registered, and hands the result to \
             one worker pool per registered consumer. It reaches NEITHER plane state. The \
             pools run beside the server on their own data-plane and control-plane stores, \
             and the tuning it hands them is not plane state. The reclassification is not \
             a formality: the check went RED on this key the moment the boot path read it, \
             which is exactly the rot-detection PR 1 was buying.\n\n\
             ONE value from this section now reaches ONE plane, and the earlier claim that \
             nothing on AdminState holds any of these knobs is no longer true. \
             `visibility_timeout_secs` is installed with \
             `AdminState::with_outbox_visibility_timeout` so the queue-depth read can say \
             what \"in flight\" means, since nothing about a claimed row records how long \
             its lease was for. It reaches ONE plane because the data plane DRAINS the \
             queue and never reports on it. It is installed from the same `Config` the \
             pools are built from, so the report and the drain cannot disagree.",
        ),
        (
            "users",
            Reach::OnePlaneOrNoState,
            "the user lifecycle settings (issue #52): whether this process executes \
             scheduled offboardings that have come due. Read once at boot by \
             offboarding_inputs, which builds the consumer and hands it to a worker pool. \
             It reaches NEITHER plane state, for the same reason `outbox`, `webhooks` and \
             `traits` do not: a pool is not plane state. The user management surface that \
             SCHEDULES an offboarding lives on AdminState and holds no knob from here.",
        ),
        (
            "traits",
            Reach::OnePlaneOrNoState,
            "the schema-driven identity trait settings (issue #53): whether this process \
             runs the migration-job worker, and how large one batch is. Read once at boot \
             by trait_migration_inputs, which builds the consumer and hands it to a worker \
             pool. It reaches NEITHER plane state, for the same reason `outbox` and \
             `webhooks` do not: a pool is not plane state. The trait SCHEMA surface that \
             validates identities lives on AdminState and holds none of these knobs.",
        ),
        (
            "flow_targets",
            Reach::OnePlaneOrNoState,
            "the async flow-target delivery consumer's own settings (issue #112 criterion \
             2): whether this process drains the queue, and the per-delivery time budget. \
             Read once at boot by flow_target_delivery_inputs, which builds the consumer and \
             its sender and hands them to a worker pool. It reaches NEITHER plane state, for \
             the same reason `outbox` and `webhooks` do not: a pool is not plane state. The \
             HTTP surface that registers targets lives on AdminState and holds none of these \
             knobs, and the SYNC dispatcher's own ceiling is a constant in ironauth-oidc \
             rather than a config value, so there is no shared value here to install.",
        ),
        (
            "webhooks",
            Reach::OnePlaneOrNoState,
            "the outbound webhook delivery consumer's own settings (issue #105): whether \
             this process drains the queue, and the per-delivery time budget. Read once at \
             boot by webhook_delivery_inputs, which builds the consumer and its sender and \
             hands them to a worker pool. It reaches NEITHER plane state, for the same \
             reason `outbox` does not: a pool is not plane state. The HTTP surface that \
             registers endpoints lives on AdminState and holds none of these knobs, so \
             there is no shared value here to install.",
        ),
        (
            "features",
            Reach::OnePlaneOrNoState,
            "the maturity ladder, resolved at boot into per-feature verdicts rather \
             than installed as a section. The two verdicts that DO reach both planes, \
             signup_quarantine and advanced_recovery, are declared in the from_boot \
             list of shared_plane_inputs! and are covered by the harness through that \
             declaration, not through this section.",
        ),
    ];

    /// Every top-level key `Config` carries, taken from `Config` ITSELF.
    ///
    /// The universe is the serialized shape of the shipped default, so it cannot fall
    /// behind the struct the way a hand written list would.
    fn config_keys() -> Vec<String> {
        let value = serde_json::to_value(ironauth_config::Config::default())
            .expect("Config serializes to a JSON object");
        value
            .as_object()
            .expect("Config is a struct, so it serializes to an object")
            .keys()
            .cloned()
            .collect()
    }

    /// Every `with_*` builder a plane state's source declares.
    ///
    /// Read out of the source text because Rust offers no way to enumerate a type's
    /// inherent methods, and the point of the census is to notice a builder nobody
    /// declared. A `.with_x(` CALL is not preceded by `fn `, so only declarations
    /// match.
    fn builder_methods(source: &str) -> BTreeSet<String> {
        source
            .split("fn with_")
            .skip(1)
            .map(|tail| {
                let name: String = tail
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                format!("with_{name}")
            })
            .collect()
    }

    /// Every body of a method named `method` in `source`, from its signature to the
    /// next method at the same indentation.
    fn method_bodies<'a>(source: &'a str, method: &str) -> Vec<&'a str> {
        let opening = format!("fn {method}(");
        source
            .match_indices(&opening)
            .map(|(start, _)| {
                let rest = &source[start..];
                let end = rest[1..].find("\n    fn ").map_or(rest.len(), |at| at + 1);
                &rest[..end]
            })
            .collect()
    }

    #[test]
    fn the_universe_of_config_keys_is_read_from_config_itself() {
        // Anchor: the derivation actually produced the sections we reason about below,
        // so a later assertion that passes cannot be passing over an empty universe.
        let keys = config_keys();
        assert!(
            keys.len() > 10,
            "Config should carry more than ten top-level keys; got {keys:?}"
        );
        for expected in ["admin", "oidc", "organizations", "token_claims"] {
            assert!(
                keys.iter().any(|key| key == expected),
                "the derived universe must contain `{expected}`; got {keys:?}"
            );
        }
    }

    #[test]
    fn every_config_key_is_either_a_declared_shared_section_or_classified_plane_local() {
        for key in config_keys() {
            let shared = SHARED_CONFIG_SECTION_NAMES.contains(&key.as_str());
            let plane_local = PLANE_LOCAL_KEYS.iter().any(|(name, _, _)| *name == key);
            assert!(
                shared || plane_local,
                "config key `{key}` is neither declared in the shared_plane_inputs! \
                 invocation nor classified in PLANE_LOCAL_KEYS. If both plane states \
                 receive it, declare it shared so ONE install body reaches both planes; \
                 if only one plane does, classify it here with the reason."
            );
            assert!(
                !(shared && plane_local),
                "config key `{key}` is declared shared AND classified plane local; it \
                 is one or the other."
            );
        }
    }

    #[test]
    fn no_classification_entry_names_a_key_config_no_longer_carries() {
        let keys = config_keys();
        for (name, _, _) in PLANE_LOCAL_KEYS {
            assert!(
                keys.iter().any(|key| key == name),
                "PLANE_LOCAL_KEYS classifies `{name}`, which Config no longer carries; \
                 a stale entry hides a renamed section from the coverage check."
            );
        }
        for name in SHARED_CONFIG_SECTION_NAMES {
            assert!(
                keys.iter().any(|key| key == name),
                "the shared_plane_inputs! invocation declares `{name}`, which Config no \
                 longer carries."
            );
        }
    }

    #[test]
    fn no_key_is_classified_twice() {
        let mut seen: Vec<&str> = Vec::new();
        for (name, _, _) in PLANE_LOCAL_KEYS {
            assert!(!seen.contains(name), "`{name}` is classified twice");
            seen.push(name);
        }
    }

    #[test]
    fn every_plane_local_classification_states_a_reason() {
        for (name, _, reason) in PLANE_LOCAL_KEYS {
            assert!(
                reason.len() > 20,
                "`{name}` is classified plane local without a stated reason: {reason:?}"
            );
        }
    }

    /// Every `.rs` file under this crate's `src/` tree, as (relative path, contents).
    ///
    /// Derived from the TREE rather than from a hand written list of `include_str!`s,
    /// because the list was the hole. Measured against a two-file list of `main.rs`
    /// and `shared_config.rs`: a real accessor read of a section classified
    /// `UnreadAtBoot`, placed in A NEW MODULE FILE OF THIS CRATE, survived the check
    /// (verified a genuine rebuild, not a stale artifact). A new module is the natural
    /// shape of the very next change these classifications are a promise about.
    ///
    /// `src/` and not the whole crate, deliberately and not by omission: the claim is
    /// about the BOOT PATH, which is what `src/` is. A `tests/` file that names a
    /// section's type is exercising it, not booting it, and the cross-crate defaults
    /// pin under `tests/` is exactly that.
    fn crate_sources() -> Vec<(String, String)> {
        fn walk(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<(String, String)>) {
            let entries = std::fs::read_dir(dir)
                .unwrap_or_else(|e| panic!("the crate source tree must be readable: {e}"));
            for entry in entries {
                let path = entry.expect("a readable directory entry").path();
                if path.is_dir() {
                    walk(&path, root, out);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    let name = path
                        .strip_prefix(root)
                        .unwrap_or(&path)
                        .display()
                        .to_string();
                    let body = std::fs::read_to_string(&path)
                        .unwrap_or_else(|e| panic!("{name} must be readable: {e}"));
                    out.push((name, body));
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        walk(&root, &root, &mut out);
        out.sort();
        out
    }

    #[test]
    fn no_key_classified_unread_is_read_by_the_boot_path() {
        let sources = crate_sources();
        // Anchors, and there are three of them because each is a way this check has
        // previously been able to pass over nothing.
        //
        // First: the walk found the whole tree, not one file and not zero.
        let names: Vec<&str> = sources.iter().map(|(name, _)| name.as_str()).collect();
        assert!(
            names.contains(&"main.rs") && names.contains(&"shared_config.rs"),
            "the scan must cover the crate's own modules; it found {names:?}"
        );
        assert!(
            sources.len() >= 3,
            "the scan must cover EVERY module in src/, not just the two that used to be \
             named here; it found {names:?}"
        );
        // Second: the file it found really is the boot path, with the same content the
        // previous `include_str!` anchor checked.
        let boot = sources
            .iter()
            .find(|(name, _)| name == "main.rs")
            .map(|(_, body)| body.as_str())
            .expect("main.rs is in the tree");
        assert!(
            boot.contains("fn serve(") && boot.contains("assemble_planes"),
            "the scanned main.rs must be the boot path"
        );
        assert_eq!(
            boot, BOOT_SOURCE,
            "the tree walk reads the same bytes the compiler does; a mismatch means the \
             scan is looking at the wrong tree"
        );
        // Third: the classification kind is exercised.
        let unread: Vec<(&str, &str)> = PLANE_LOCAL_KEYS
            .iter()
            .filter_map(|(name, reach, _)| match reach {
                Reach::UnreadAtBoot { config_type } => Some((*name, *config_type)),
                Reach::OnePlaneOrNoState => None,
            })
            .collect();
        assert!(
            !unread.is_empty(),
            "the classification kinds must be exercised: with no UnreadAtBoot entry \
             this check would pass over an empty list. Remove the kind rather than \
             leave it inert."
        );

        for (key, config_type) in unread {
            // A field read is `something.key`. Scanning for the accessor rather than the
            // bare word keeps the classification list's own quoted key names from
            // matching themselves.
            let accessor = format!(".{key}");
            for (file, source) in &sources {
                assert!(
                    !source.contains(&accessor),
                    "`{key}` is classified as read by NO boot path, but src/{file} \
                     contains `{accessor}`. Either the claim is stale (reclassify it) or \
                     the read is new, and if BOTH planes now receive it, declare it shared."
                );
                // The accessor scan alone is not enough, and that is measured rather than
                // assumed: a struct-destructuring bind of the section out of `Config`,
                // and a function parameter typed as the section's own type, both survive
                // it. A section cannot reach any boot path without its TYPE being named
                // somewhere, so the type name is the second half of the check.
                //
                // THIS file is allowed exactly ONE mention, the declaration in
                // PLANE_LOCAL_KEYS above, and it is COUNTED rather than exempted: a
                // second mention here is a read like any other.
                let allowed = usize::from(file == "shared_config.rs");
                assert_eq!(
                    source.matches(config_type).count(),
                    allowed,
                    "`{key}` is classified as read by NO boot path, but src/{file} names \
                     its type `{config_type}` more often than the {allowed} time(s) the \
                     classification itself needs. A destructuring bind or a typed \
                     parameter reads the section without ever writing `{accessor}`."
                );
            }
        }
    }

    #[test]
    fn the_builders_both_plane_states_offer_are_exactly_the_declared_shared_values() {
        let admin = builder_methods(ADMIN_STATE_SOURCE);
        let oidc = builder_methods(OIDC_STATE_SOURCE);
        // Anchor: the census read real builders off both states. A parse that produced
        // nothing would make the comparison below pass over two empty sets.
        assert!(
            admin.len() >= 5 && oidc.len() >= 15,
            "the builder census must find each state's builders; found {} on the \
             management plane and {} on the data plane",
            admin.len(),
            oidc.len()
        );
        let both: BTreeSet<String> = admin.intersection(&oidc).cloned().collect();
        let declared: BTreeSet<String> = SHARED_PLANE_BUILDERS
            .iter()
            .map(|(_, builder)| (*builder).to_owned())
            .collect();
        assert_eq!(
            both, declared,
            "a builder BOTH plane states offer is a cross-plane value: the boot path can \
             install it on each plane by hand, from separate values, and nothing else \
             would notice. Declare it in the shared_plane_inputs! invocation so ONE \
             captured value reaches both planes through ONE install body. This is the \
             backstop for the boot-sourced values, which the whole-of-Config check \
             cannot see."
        );
    }

    #[test]
    fn every_declared_builder_is_the_one_both_install_bodies_call() {
        assert!(
            !SHARED_PLANE_BUILDERS.is_empty(),
            "the declaration must yield at least one installed value"
        );
        for (install, builder) in SHARED_PLANE_BUILDERS {
            let bodies = method_bodies(THIS_SOURCE, install);
            assert_eq!(
                bodies.len(),
                2,
                "`{install}` must be implemented exactly twice, once per plane; found {}",
                bodies.len()
            );
            let call = format!(".{builder}(");
            for body in bodies {
                assert!(
                    body.contains(&call),
                    "`{install}` is declared to install through `{builder}`, but one of \
                     its two bodies never calls it. The builder census is measured \
                     against that declared name, so a name the body does not keep would \
                     let an undeclared cross-plane builder pass."
                );
            }
        }
    }
}
