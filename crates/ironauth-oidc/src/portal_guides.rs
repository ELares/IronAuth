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
//! 0183), so a guide exists for every value a row can hold and the fallback arm is unreachable
//! from stored data. It is still written, because the column is read as a string and a guide that
//! silently rendered nothing for an unexpected value would leave the page missing a section with
//! no sign that anything was wrong.

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
        // THE FALLBACK IS ALSO THE `generic` GUIDE, deliberately: the two say the same thing,
        // because what a provider without a named console needs is the protocol facts.
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
