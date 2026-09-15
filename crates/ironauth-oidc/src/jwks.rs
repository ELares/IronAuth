// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-issuer JWKS HTTP surface.
//!
//! Serving JWKS with operational discipline is where OSS providers are ad hoc.
//! Every JWKS response here carries an explicit `Cache-Control` (a `max-age`
//! bounded to the 300-to-900-second range) and a strong `ETag`, and a conditional
//! request (`If-None-Match`) that matches returns `304 Not Modified` with no body
//! (the shared [`crate::wellknown`] discipline). That is what lets a relying party
//! cache the key set, refetch cheaply on a `kid` miss (the documented RP
//! contract), and never hammer the endpoint.
//!
//! The route is per issuer, since every environment has its own issuer and key
//! set:
//!
//! - `GET /t/{tenant_id}/e/{environment_id}/jwks.json`
//!
//! It resolves the environment through the [`IssuerRegistry`]; an unknown or
//! malformed scope is a `404`.
//!
//! # Relationship to discovery and to key loading (issue #194)
//!
//! Discovery (both well-known forms) is served independently by
//! [`crate::discovery`], which needs only live config, the issuer string, and the
//! per-environment algorithm policy: NOT the loaded signing keys. This JWKS
//! surface DOES need the loaded keys, and is now mounted on the live data plane
//! (issue #194). The [`IssuerRegistry`] that backs it is store-backed and LAZY: it
//! reads a scope's keys through the RLS-forced [`ironauth_store::Store::scoped`] on
//! the first request for that issuer and caches the result, so an unprovisioned or
//! cross-tenant environment loads zero rows and yields a uniform 404.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use ironauth_env::Env;

use ironauth_jose::{JwkSet, SigningKey};
use ironauth_store::Scope;
use ironauth_store::session_token_store::SessionTokenKeyRecord;

use crate::issuer::IssuerRegistry;
use crate::session_tokenizer;
use crate::wellknown::{cacheable_response, not_found, parse_scope};

/// The media type for a JWK Set (RFC 7517).
const JWK_SET_MEDIA_TYPE: &str = "application/jwk-set+json";

/// The shared state for the JWKS surface: the registry and the clock seam.
#[derive(Clone)]
pub struct IssuerState {
    registry: Arc<IssuerRegistry>,
    env: Env,
    // The per-template published document, cached so a verifier can still refetch during a
    // store outage (issue #1279).
    //
    // WHY THIS EXISTS SEPARATELY FROM THE REGISTRY'S CACHE. The environment's JWKS resolves
    // through `IssuerRegistry::resolve_for_publication`, which caches an entry per SCOPE and
    // serves a fresh one when the store cannot answer (issues #149, #1261). A template's key
    // set is not on that entry: it is per (scope, template), loaded by its own two reads, and
    // the registry has nowhere to put it.
    //
    // So this surface had no cache at all and returned 500 on any store error, on the URL its
    // own doc calls "the URL criterion 1 rests on: a verifier fetches it, caches it, and checks
    // a tokenized session JWT against it with NO database call". A verifier whose cache expired
    // mid-incident could not refetch, which is the exact failure #149 criterion 2 exists to
    // prevent, on a surface the criterion's letter does not name.
    //
    // Behind an `Arc` because `IssuerState` is cloned per request by axum's `State` extractor;
    // without it every request would carry its own empty cache.
    template_jwks: Arc<RwLock<HashMap<(Scope, String), CachedTemplateKeys>>>,
}

/// One template's published key ROWS, with the instant they were read.
///
/// THE ROWS AND NOT THE RENDERED DOCUMENT, which the first version of this cached. A key is
/// published from `publish_at` until `expire_at`, and rendering freezes that filter into the
/// bytes: a review rotated a key out, advanced the clock INSIDE the freshness window, and got a
/// 200 still naming the withdrawn kid while the live store answered `{"keys":[]}`. That is the
/// harm #204 names as the reason a STALE set is refused, delivered on the FRESH path.
///
/// Caching the rows and re-applying the window at request time is what the environment JWKS
/// already does: it holds a `KeySet` and calls `published_jwks(now, policy)` per request rather
/// than storing a document.
#[derive(Debug, Clone)]
struct CachedTemplateKeys {
    keys: Vec<SessionTokenKeyRecord>,
    read_at: SystemTime,
}

impl IssuerState {
    /// Build the issuer state from a registry and the environment seam.
    #[must_use]
    pub fn new(registry: Arc<IssuerRegistry>, env: Env) -> Self {
        Self {
            registry,
            env,
            template_jwks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// The freshly cached document for `key`, or [`None`] when there is none or it is stale.
    ///
    /// STALE IS NEVER SERVED, which is the same rule the entry cache follows and for the same
    /// reason #204 gives: serving a stale key set would extend the window in which a rotated-out
    /// key is still trusted. An outage that outlasts the window closes the surface rather than
    /// widening that window.
    fn fresh_template_keys(
        &self,
        key: &(Scope, String),
        now: SystemTime,
    ) -> Option<Vec<SessionTokenKeyRecord>> {
        let ttl = self.registry.cache().max_age();
        let cached = self.template_jwks.read().ok()?;
        let entry = cached.get(key)?;
        let age = now.duration_since(entry.read_at).ok()?;
        (age < ttl).then(|| entry.keys.clone())
    }

    /// Remember `keys` as `key`'s published rows, read at `now`.
    ///
    /// AN EMPTY SET IS NEVER REMEMBERED. `JwkSet::from_signing_keys(empty)` is `Ok`, so
    /// `{"keys":[]}` would otherwise become a legitimate cached "fresh document": a template
    /// between key generations, or a node whose clock trails the control plane that stamped
    /// `publish_at`, would cache it and then publish it for the whole window during an outage.
    /// A verifier caches that as "this issuer publishes no keys" and rejects every token
    /// against it, which is the outage this handler's own 404-on-missing comment exists to
    /// avoid. Caching nothing means such a request 500s during an outage, which is a fault a
    /// client retries rather than a wrong answer it caches.
    fn remember_template_keys(
        &self,
        key: (Scope, String),
        keys: &[SessionTokenKeyRecord],
        now: SystemTime,
    ) {
        if keys.is_empty() {
            return;
        }
        if let Ok(mut cached) = self.template_jwks.write() {
            cached.insert(
                key,
                CachedTemplateKeys {
                    keys: keys.to_vec(),
                    read_at: now,
                },
            );
        }
    }

    /// The issuer registry.
    #[must_use]
    pub fn registry(&self) -> &IssuerRegistry {
        &self.registry
    }
}

impl std::fmt::Debug for IssuerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuerState").finish_non_exhaustive()
    }
}

/// Build the per-issuer JWKS router.
///
/// Mount it on the PUBLIC data plane alongside the protocol and discovery routers
/// once per-environment signing keys are loaded (issue #194).
pub fn issuer_router(state: IssuerState) -> Router {
    Router::new()
        .route("/t/{tenant_id}/e/{environment_id}/jwks.json", get(jwks))
        // ONE TEMPLATE'S OWN key set (issue #119). Mounted here rather than beside the tokenize
        // endpoint because it is the same kind of document with the same caching discipline,
        // and because a reader looking for "which JWKS does this deployment publish" must find
        // both in one place.
        .route(
            "/t/{tenant_id}/e/{environment_id}/session-tokens/{template}/jwks.json",
            get(template_jwks),
        )
        .with_state(state)
}

/// `GET .../jwks.json`: the environment's published JWKS, with explicit
/// `Cache-Control`, a strong `ETag`, and `304` on a matching `If-None-Match`.
async fn jwks(
    State(state): State<IssuerState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    let now = state.env.clock().now_utc();
    let body = match state.registry.jwks_json(&scope, now).await {
        Some(Ok(body)) => body,
        // Unregistered environment: a uniform not-found.
        None => return not_found(),
        // A malformed stored key is an internal fault, not a caller error.
        Some(Err(_)) => return server_error(),
    };
    cacheable_response(
        &headers,
        JWK_SET_MEDIA_TYPE,
        state.registry.cache().max_age_secs(),
        &body,
    )
}

/// `GET /t/{tenant}/e/{environment}/session-tokens/{template}/jwks.json`: one template's OWN
/// published key set.
///
/// This is the URL criterion 1 rests on: a verifier fetches it, caches it, and checks a
/// tokenized session JWT against it with NO database call and no IronAuth involvement.
///
/// It is a SEPARATE document from the environment's `jwks.json`, and a template's key never
/// appears in that one. See migration 0173 for why the separation is structural rather than a
/// filter, and `id::SessionTokenKeyKind` for why the identifiers cannot be confused either.
async fn template_jwks(
    State(state): State<IssuerState>,
    Path((tenant_id, environment_id, template)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    let Some(store) = state.registry().store() else {
        return not_found();
    };
    let now = state.env.clock().now_utc();
    let now_micros = crate::util::epoch_micros(now);
    let cache_key = (scope, template.clone());

    // AN UNREADABLE STORE PUBLISHES FROM THE FRESH CACHED ROWS rather than 500ing (#1279).
    //
    // This surface is the one its own doc calls "the URL criterion 1 rests on: a verifier
    // fetches it, caches it, and checks a tokenized session JWT against it with NO database
    // call". Returning 500 meant a verifier whose cache expired mid-incident could not refetch,
    // so tokens that were still perfectly valid stopped validating because the ISSUER was
    // having a bad day. The environment's JWKS has been protected from that since #1261.
    //
    // ONLY A PERSISTENCE FAULT IS SOFTENED. `published_keys` returns `Err` for TWO different
    // things, which its own rustdoc says: "on a persistence fault, OR if a stored row fails to
    // decode". The first version routed both here, and a review corrupted a key row's `id` and
    // got a 200 serving the last good document, on a template whose material is unreadable,
    // while `main` had returned 500. That turned a surfaced data fault into a healthy-looking
    // success with a full max-age, which is the exact opposite of the trade this makes.
    //
    // A decode failure surfaces as something other than `Database` (`NotInScope` converts to
    // `NotFound`), so matching on the variant is what separates "the store could not answer"
    // from "the store answered and the answer is broken".
    macro_rules! published_or_cached {
        ($result:expr) => {
            match $result {
                Ok(keys) => keys,
                Err(ironauth_store::StoreError::Database(_)) => {
                    match state.fresh_template_keys(&cache_key, now) {
                        Some(keys) => keys,
                        None => return server_error(),
                    }
                }
                Err(_) => return server_error(),
            }
        };
    }

    // The template must EXIST for its JWKS to answer. Without this check a misspelled name
    // would return an empty key set with a 200, which a verifier caches as "this issuer
    // publishes no keys" and then rejects every token against for the whole cache window --
    // an outage that reads as a signing problem rather than as a typo.
    //
    // A TEMPLATE READ AND FOUND ABSENT STILL 404s. Only an unreadable store is softened; a
    // known answer keeps its own. What this does NOT do, stated because an earlier version of
    // this comment claimed the asymmetry was "the same one `resolve_for_publication`
    // documents" and it is not: that contract has three arms and refuses a FENCED scope, read
    // through its own fence check. This handler has no fence read at all, so a suspended scope
    // publishes here whether or not a cache exists -- and DURING AN OUTAGE the cache widens
    // that, because before this change such a request needed a live store. The window is one
    // freshness period per node. Tracked as its own question rather than smuggled in here.
    let keys = match store
        .scoped(scope)
        .session_token_templates()
        .get(&template)
        .await
    {
        Ok(Some(_)) => published_or_cached!(
            store
                .scoped(scope)
                .session_token_templates()
                .published_keys(&template, now_micros)
                .await
        ),
        Ok(None) => return not_found(),
        Err(ironauth_store::StoreError::Database(_)) => {
            match state.fresh_template_keys(&cache_key, now) {
                Some(keys) => keys,
                None => return server_error(),
            }
        }
        Err(_) => return server_error(),
    };

    // THE PUBLICATION WINDOW IS RE-APPLIED AT REQUEST TIME, against the live clock, whether the
    // rows came from the store or from the cache. The store's own query filters on it, so this
    // is a no-op for a fresh read and is the whole point for a cached one: a review advanced
    // the clock past a rotated-out key's `expire_at` INSIDE the freshness window and got a
    // document still naming it.
    let published: Vec<SessionTokenKeyRecord> = keys
        .into_iter()
        .filter(|key| {
            key.publish_at_unix_micros <= now_micros
                && key
                    .expire_at_unix_micros
                    .is_none_or(|expire| expire > now_micros)
        })
        .collect();
    // AND AN EMPTY RESULT IS NOT A DOCUMENT. Re-applying the window can empty a cached set, and
    // publishing `{"keys":[]}` is the "this issuer publishes no keys" outage described above.
    if published.is_empty() {
        return server_error();
    }

    let loaded: Result<Vec<SigningKey>, session_tokenizer::MintError> = published
        .iter()
        .map(session_tokenizer::load_template_key)
        .collect();
    let Ok(loaded) = loaded else {
        return server_error();
    };
    let Ok(set) = JwkSet::from_signing_keys(loaded.iter()) else {
        return server_error();
    };
    let Ok(body) = set.to_json() else {
        return server_error();
    };
    state.remember_template_keys(cache_key, &published, now);
    cacheable_response(
        &headers,
        JWK_SET_MEDIA_TYPE,
        state.registry().cache().max_age_secs(),
        &body,
    )
}

/// A `500` for an internal fault (a malformed stored key).
fn server_error() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "server error\n").into_response()
}
