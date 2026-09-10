// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-identity-provider setup guides the self-service portal renders (issue #140).
//!
//! # Why these are code and not a documentation link
//!
//! #140's fourth acceptance criterion asks that "setup guides render per IdP with correct
//! copy-paste values for the specific connection being configured", and the operative half is
//! the second: a customer's IT admin following a generic vendor doc has to work out which of
//! their connections it is about and what this deployment's URL is. A guide rendered beside the
//! connection knows both, so the values in it cannot be the wrong ones for the row it sits under.
//!
//! # What a guide may and may not contain
//!
//! It may contain values a portal session is already entitled to see: the deployment's SCIM base
//! URL, the connection's own display name and provider. It may NOT contain the bearer token. The
//! token exists in plaintext exactly once, in the response to the create or rotate call that
//! minted it, and the store holds only its digest -- so a guide that offered to show it would be
//! promising something no reader can produce. Each guide says where the token comes from instead,
//! which is the vendor, and every one of them says it: an admin who reaches this page without a
//! token needs to know who to ask.
//!
//! # The provider set is closed and comes from the database
//!
//! `scim_connections.provider` is `CHECK (provider IN ('okta', 'entra', 'generic'))` (migration
//! 0183), so a guide exists for every value a row can hold.
//!
//! THE CATCH-ALL ARM IS THE `generic` GUIDE, not an unreachable fallback: every connection whose
//! provider is `generic` takes it, and that is a value a vendor chooses explicitly -- the
//! management API requires `provider` on create and refuses anything outside the three. The
//! column also DEFAULTS to `generic`, but no writer relies on that default, so the reachability
//! that matters is the explicit one.
//!
//! It doubles as the fallback because what a provider without a named console needs is the
//! protocol facts, and those are the same facts an unexpected value would need. Writing it as `_`
//! rather than `"generic" | _` is deliberate: an unexpected value must render a usable guide
//! rather than leave the page silently missing a section.

/// One identity provider's setup guide, already resolved for a specific connection.
pub(crate) struct SetupGuide {
    /// The provider's operator-facing name, as its own console spells it.
    pub(crate) provider_name: &'static str,
    /// Where in that console the SCIM settings live.
    pub(crate) where_to_go: &'static str,
    /// The ordered steps, each naming the field it fills where the provider has a name for it.
    pub(crate) steps: Vec<String>,
}

/// The guide for `provider`, with `scim_base` filled into the steps that need it.
///
/// `scim_base` is the deployment's own SCIM endpoint, which is why this takes it rather than
/// composing it: the portal page derives it from the state it was built with, and a second
/// derivation here could disagree with the one printed above the table.
pub(crate) fn guide_for(provider: &str, scim_base: &str) -> SetupGuide {
    match provider {
        "okta" => SetupGuide {
            provider_name: "Okta",
            where_to_go: "In Okta, open your application and select the Provisioning tab, then \
                          Configure API Integration.",
            steps: vec![
                "Tick Enable API integration.".to_owned(),
                format!("Put {scim_base} in the Base URL field."),
                "Put the token your vendor gave you in the API Token field. It is shown once, \
                 when the connection is created or its token is rotated, and cannot be read back \
                 afterwards -- ask your vendor to rotate it if you no longer have it."
                    .to_owned(),
                "Select Test API Credentials, then Save.".to_owned(),
                "Under To App, enable Create Users, Update User Attributes and Deactivate Users \
                 so that changes in Okta reach this application."
                    .to_owned(),
            ],
        },
        "entra" => SetupGuide {
            provider_name: "Microsoft Entra ID",
            where_to_go: "In Entra, open Enterprise applications, choose your application, and \
                          select Provisioning.",
            steps: vec![
                "Set Provisioning Mode to Automatic.".to_owned(),
                format!("Put {scim_base} in the Tenant URL field."),
                "Put the token your vendor gave you in the Secret Token field. It is shown once, \
                 when the connection is created or its token is rotated, and cannot be read back \
                 afterwards -- ask your vendor to rotate it if you no longer have it."
                    .to_owned(),
                "Select Test Connection, then Save.".to_owned(),
                "Set Provisioning Status to On, and check the Scope setting decides which users \
                 and groups are sent."
                    .to_owned(),
            ],
        },
        // `generic` AND ANYTHING UNEXPECTED, deliberately the same arm: see the module doc. A
        // vendor chooses `generic` explicitly, so this is an ordinary case rather than a
        // fallback.
        _ => SetupGuide {
            provider_name: "your identity provider",
            where_to_go: "In your identity provider's SCIM or provisioning settings:",
            steps: vec![
                format!(
                    "Set the SCIM 2.0 base URL to {scim_base}. Your provider may call this the \
                     base URL, the tenant URL, or the endpoint."
                ),
                "Set the authentication method to a bearer token, and use the token your vendor \
                 gave you. It is shown once, when the connection is created or its token is \
                 rotated, and cannot be read back afterwards -- ask your vendor to rotate it if \
                 you no longer have it."
                    .to_owned(),
                "Enable user provisioning, and group provisioning if your provider offers it \
                 separately."
                    .to_owned(),
            ],
        },
    }
}

/// Which identity provider a SAML connection's own published entity id names.
///
/// # Best effort, and the fallback is the design rather than a gap
///
/// `scim_connections` carries a `provider` column with a CHECK, so the SCIM guides above key on
/// a value a vendor chose. `saml_connections` has no such column. The signal available is the
/// `idp_entity_id` the identity provider itself publishes, and the three that matter announce
/// themselves in it: Okta issues `http://www.okta.com/exk...`, Entra
/// `https://sts.windows.net/{directory}/`, Google `https://accounts.google.com/o/saml2?idpid=...`.
///
/// A DEPLOYMENT WITH A CUSTOM ENTITY ID GETS THE GENERIC GUIDE, which is a degraded answer and
/// not a wrong one: the generic guide names the same protocol facts and the same copy-paste
/// values, and it is what an admin at a provider with no named console needs anyway. That is
/// the whole reason this is allowed to be a substring test. A classifier whose misses produced
/// WRONG instructions rather than plainer ones would not be.
///
/// Matched case-insensitively on the host-ish part, because entity ids are transcribed by hand
/// into both systems and their case is not normalized anywhere.
pub(crate) fn saml_provider_of(idp_entity_id: &str) -> &'static str {
    let lowered = idp_entity_id.to_ascii_lowercase();
    if lowered.contains("okta.com") {
        "okta"
    } else if lowered.contains("sts.windows.net") || lowered.contains("microsoftonline.com") {
        "entra"
    } else if lowered.contains("accounts.google.com") {
        "google"
    } else {
        "generic"
    }
}

/// The SAML setup guide for the identity provider `idp_entity_id` names.
///
/// Takes the three values rather than composing them, for the reason [`guide_for`] does: the
/// page derives them from the connection row and the state it was built with, and a second
/// derivation here could disagree with the one printed beside the guide.
/// `metadata_url` is [`None`] when the connection is switched off, because
/// `saml_metadata::metadata_get` reads through `find_active` and the document 404s until it
/// is back on. The step is DROPPED rather than reworded: an instruction to import a document
/// that is not served is the one kind of wrong a setup guide must not be.
pub(crate) fn saml_guide_for(
    idp_entity_id: &str,
    acs_url: &str,
    sp_entity_id: &str,
    metadata_url: Option<&str>,
) -> SetupGuide {
    match saml_provider_of(idp_entity_id) {
        "okta" => SetupGuide {
            provider_name: "Okta",
            where_to_go: "Applications, your app, then the Sign On tab.",
            steps: vec![
                "Select Edit under SAML Settings.".to_owned(),
                format!("Put {acs_url} in Single sign-on URL."),
                format!("Put {sp_entity_id} in Audience URI (SP Entity ID)."),
                "Set Name ID format to EmailAddress and Application username to Email.".to_owned(),
                "Under Attribute Statements add email, firstName and lastName, so the people \
                 who sign in arrive with names rather than only an identifier."
                    .to_owned(),
                "Save, then use View SAML setup instructions to copy Okta's signing \
                 certificate and give it to your vendor."
                    .to_owned(),
            ],
        },
        "entra" => SetupGuide {
            provider_name: "Microsoft Entra ID",
            where_to_go: "Enterprise applications, your app, then Single sign-on.",
            steps: vec![
                "Choose SAML as the sign-on method.".to_owned(),
                format!(
                    "Under Basic SAML Configuration put {sp_entity_id} in Identifier (Entity ID)."
                ),
                format!("Put {acs_url} in Reply URL (Assertion Consumer Service URL)."),
                "Under Attributes and Claims leave the Unique User Identifier as \
                 user.userprincipalname, and confirm emailaddress, givenname and surname are \
                 present."
                    .to_owned(),
                "Under SAML Certificates download Certificate (Base64) and give it to your \
                 vendor. Entra will not show it again after you rotate it."
                    .to_owned(),
            ],
        },
        "google" => SetupGuide {
            provider_name: "Google Workspace",
            where_to_go: "Admin console, Apps, Web and mobile apps, your SAML app.",
            steps: vec![
                "Open Service provider details.".to_owned(),
                format!("Put {acs_url} in ACS URL."),
                format!("Put {sp_entity_id} in Entity ID."),
                "Leave Signed response unticked and set Name ID format to EMAIL, with Name ID \
                 as Basic Information > Primary email."
                    .to_owned(),
                "Under Attribute mapping map Primary email to email, First name to firstName \
                 and Last name to lastName."
                    .to_owned(),
                "Back on the app's page download the IDP metadata and give it to your vendor, \
                 then turn the app ON for the right organizational units -- a Google SAML app \
                 is off for everyone until you do, and the sign-in fails with no other sign."
                    .to_owned(),
            ],
        },
        // THE CATCH-ALL IS THE PROTOCOL FACTS, for the same reason the SCIM generic guide is:
        // a provider this deployment has no console instructions for still needs the same three
        // values, and a page that rendered no guide at all would leave the admin with nothing.
        _ => {
            let mut steps = vec![
                format!(
                    "Set the assertion consumer service URL, which your provider may call the \
                     ACS URL, Reply URL or Single sign-on URL, to {acs_url}."
                ),
                format!(
                    "Set the audience, which your provider may call the Entity ID, Identifier \
                     or SP Entity ID, to {sp_entity_id}."
                ),
            ];
            if let Some(metadata_url) = metadata_url {
                steps.push(format!(
                    "If your provider can import a metadata document, point it at \
                     {metadata_url} instead of typing the two values above."
                ));
            }
            steps.push(
                "Send the assertion with the person's email address as the Name ID, in \
                 EmailAddress format."
                    .to_owned(),
            );
            steps.push(
                "Give your vendor your provider's signing certificate, or the URL of its \
                 metadata document."
                    .to_owned(),
            );
            SetupGuide {
                provider_name: "your identity provider",
                where_to_go: "wherever it lists SAML or SSO applications.",
                steps,
            }
        }
    }
}

/// The setup guide for a connector upstream, by the protocol the connector declares.
///
/// NOT PER PROVIDER, and the difference from SAML is a fact about the protocols rather than an
/// omission. What an admin configures upstream is a redirect URI and then a client id and
/// secret they hand back; the console wording varies but the value does not, and there is no
/// per-provider field layout to walk through the way a SAML attribute mapping has one.
///
/// # It IS per protocol, and getting that wrong gives wrong instructions
///
/// `Protocol::Oauth2` (issue #74, GitHub being the example) binds through the same
/// `org_connections` table as an OIDC connector, and an earlier version of this guide told
/// every one of them to grant an `openid` scope. GitHub has no such scope and no issuer URL,
/// so the admin follows the step, fails to find the field, and has been sent looking for
/// something their provider does not have. That is the failure mode the SAML classifier above
/// is allowed to avoid by degrading to a generic guide; this one avoids it by reading the
/// protocol the connector actually declares.
///
/// An unreadable or unrecognised protocol takes the arm that claims LEAST: the redirect URI
/// and the credentials are true of both, the scopes and the issuer are not.
pub(crate) fn upstream_guide(protocol: Option<&str>, redirect_uri: &str) -> SetupGuide {
    let redirect_step = format!(
        "Set the redirect URI, which your provider may call the callback URL or reply URL, to \
         {redirect_uri}. It has to match exactly, including the scheme and any trailing path."
    );
    let create_step = "Create an application, choosing the web or server-side type. It must be \
                       the confidential kind, the one that gets a client secret."
        .to_owned();
    match protocol {
        Some("oauth2") => SetupGuide {
            provider_name: "your provider",
            where_to_go: "wherever it lists OAuth applications.",
            steps: vec![
                create_step,
                redirect_step,
                "Grant the scopes that expose the person's profile and their VERIFIED email \
                 address. Which they are called depends on the provider, and your vendor will \
                 tell you: there is no OpenID Connect here, so there is no openid scope and no \
                 discovery document to point at."
                    .to_owned(),
                "Give your vendor the client id and the client secret.".to_owned(),
            ],
        },
        Some("oidc") => SetupGuide {
            provider_name: "your identity provider",
            where_to_go: "wherever it lists OpenID Connect applications.",
            steps: vec![
                create_step,
                redirect_step,
                "Grant the openid, profile and email scopes, so the people who sign in arrive \
                 with a name and an address rather than only an identifier."
                    .to_owned(),
                "Give your vendor the client id, the client secret, and your provider's issuer \
                 URL -- the one its discovery document sits under."
                    .to_owned(),
            ],
        },
        _ => SetupGuide {
            provider_name: "your provider",
            where_to_go: "wherever it lists applications that sign people in.",
            steps: vec![
                create_step,
                redirect_step,
                "Ask your vendor which scopes this connection needs, and what else they need \
                 back beyond the client id and secret. This deployment could not read the \
                 protocol off the connection, so these are the steps that hold either way."
                    .to_owned(),
            ],
        },
    }
}

/// The protocol a connector's stored definition declares, if it says.
///
/// Read from `definition_json` rather than from a column, because that is where it lives: the
/// definition is the secret-free document the federation runtime itself parses.
pub(crate) fn connector_protocol(definition_json: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(definition_json)
        .ok()?
        .get("protocol")?
        .as_str()
        .map(str::to_owned)
}
