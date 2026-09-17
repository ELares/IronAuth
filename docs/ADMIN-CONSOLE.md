<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Admin console

The IronAuth console is a browser client of the public management API. It is
embedded in the Rust binary and opens at `/admin/` on the public listener when
enabled. You can manage identities, organizations, federation connections, and
client registration, and investigate authentication and policy decisions.

The console covers a subset of the management API. Use the
[capability guide](CAPABILITIES.md) for the broader platform, the
[management OpenAPI document](openapi/management.json) for exact operations and
request schemas, and the [configuration reference](CONFIG.md) for deployment
settings. The [SPA README](../packages/admin-spa/README.md) covers development and
standalone hosting.

## Enable and configure sign-in

`admin_spa.enabled` defaults to `false`. When disabled, `/admin` and its deeper
paths return 404. Enabling it serves the working console, but does not create an
administrator, register a console client, or populate the admin issuer.

Set up these prerequisites before signing in:

1. Run a migrated database with the control and data plane connections required
   by the [deployment guide](OPERATIONS.md). The management plane currently mounts
   only when `admin.bootstrap_operator_token` is configured. Keep that credential
   on the operator side; the browser never needs it. User management also needs
   the platform master key to seal and open PII.
2. Enable OIDC and provision the admin issuer's tenant and environment. Use their
   actual IronAuth identifiers, rather than display names, in the configuration.
3. Register a **public** console OAuth client in that issuer for Authorization
   Code + PKCE, with the exact callback `https://YOUR_CONSOLE_HOST/admin/`. The
   console requests `openid ironauth.manage`; it has no client secret. Register
   the client through the issuer's DCR endpoint using the management API's
   policy/initial-access-token controls. There is no generic management API
   create-client operation. Inspect and verify the registered client as needed.
   The current SPA does not send DPoP proofs. From the operator side, explicitly
   enable this client's bearer-token exception with `setClientBearerTokens`:

   ```text
   PUT /v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/bearer-tokens
   ```

   ```json
   {"allowed":true}
   ```

   Use the admin issuer's scope and this console client ID. The write requires
   configuration authority and fresh privilege under the deployment's sudo
   policy. This exception permits unbound bearer tokens for this client, making
   a stolen token replayable until expiry; it leaves other public clients'
   DPoP requirement intact. Do not put the operator credential in the browser.
4. Register the management resource audience under the admin issuer using the
   supported [snapshot/promotion workflow](snapshot/README.md). Configure the
   same exact audience in `admin_spa.management_audience`; the console sends
   it as the OAuth `resource` parameter. The management plane accepts only tokens
   with the configured issuer and exact audience, not an ordinary application
   access token from another client or resource.
5. Create the intended administrator and configure a usable sign-in credential
   in the admin issuer. Add that administrator's actual OIDC `sub` to
   `admin_spa.operator_subjects`. An empty allowlist authorizes nobody, and an
   authenticated subject outside the allowlist cannot administer the deployment.
6. Enable the console and apply the configuration. Check readiness and startup
   logs for the OIDC bridge and management plane before opening `/admin/`.

This fragment shows the console settings to add to an otherwise working
deployment. Replace every example identifier and audience with your provisioned
values; it is not a complete server configuration:

```toml
[admin_spa]
enabled = true
admin_issuer_tenant = "YOUR_ADMIN_TENANT_ID"
admin_issuer_environment = "YOUR_ADMIN_ENVIRONMENT_ID"
console_client_id = "YOUR_PUBLIC_CONSOLE_CLIENT_ID"
management_audience = "https://auth.example.com/management"
operator_subjects = ["YOUR_ADMIN_OIDC_SUBJECT"]
```

The server injects the nonsecret issuer path, public client ID, and audience into
the console's entry document. Its `/admin/api` proxy forwards browser requests to
the in-process management router, using only the browser's own bearer credential.
The proxy is available only when OIDC and the issuer/audience bridge are
configured and the management plane is mounted.

## Sign-in, MFA, and session behavior

Select **Sign in** to start an OIDC Authorization Code flow with S256 PKCE and
CSRF state validation. IronAuth's issuer presents the authentication pages and any
required MFA, passkey, recovery, or consent steps according to its enabled
features and policies. The console does not supply a separate administrator
password or bypass those policies. See [headless flows](FLOWS.md) and
[step-up authentication](design/step-up-authentication.md) for the authentication
contract and assurance rules.

The short-lived management access token stays in browser memory. Reloading the
page requires sign-in again; an existing issuer session may let that sign-in
complete without another credential prompt. The selected tenant/environment IDs
persist in `sessionStorage`, and the PKCE verifier and state are stored there
temporarily across the redirect and consumed on return. Bearer tokens are not
stored in browser storage.

**Sign out of console** clears the in-memory token and selected context. It does
not call the issuer's logout endpoint or revoke other sessions. When a privileged
write returns a `max_age` challenge, the error panel can offer **Re-authenticate
to continue**, requesting a fresh login with `max_age` and `prompt=login`.
Re-authentication navigates away; the original mutation and draft are not
persisted across the callback. Return to the affected page and re-enter the
action after sign-in. Sudo requirements remain enforced by the management API
in the active environment. The console is not a full MFA enrollment, password
reset, or end-user account settings interface.

## Find resources and choose a context

The sidebar groups pages into **Workspace**, **Identity**, and **Operations**.
The header's tenant/environment selector controls the scope of resource pages;
changing it reloads scoped content and discards drafts and one-time credential
output from the previous scope. When the loaded context resolves to one tenant
and one environment, the selector collapses and the environment is implicit.
Pages without a required selection show guidance instead of sending an unscoped
request.

The visible search control and **Cmd/Ctrl+K** open the command palette. Search
page names and the tenant/environment names already loaded by the console, then
use Arrow Up/Down and Enter to navigate. Escape closes it and restores focus.
This is navigation search, not a server-wide user or resource search.

Resource collections show their loaded rows first. Where a list offers a local
filter, it searches only those rows. The current console does not browse every
cursor page: paginated organization, invitation, role, group, permission, and
resource-server panels report when additional results exist. The tenant,
environment, user, and connector wrappers also load only the initial API page;
their displayed counts and filters do not establish deployment-wide totals.
Use the management API with its opaque `next_cursor` for complete inventories.

Creation and grant forms open only after you select the relevant **Create**,
**Add**, **Grant**, or **Configure** action. Empty lists do not automatically open
a form. Cancel, the close control, or Escape discards the draft and returns focus
to the action; dismissal is disabled while a submitted request is pending. On
success the dialog closes, and confirmation or issued credential output stays on
the page. Destructive and lifecycle actions have an explicit confirmation step.

## Pages and supported operations

Paths below are browser routes under the embedded `/admin` mount. Tenant detail
uses the route's tenant ID, environment detail uses the active tenant, and
identity detail routes combine their resource ID with the active
tenant/environment selection.

| Page | Browser path | What you can do |
| --- | --- | --- |
| Overview | `/admin/` | See loaded tenant and environment counts, the active environment, and navigation shortcuts. These are context summaries, not live identity counts or an analytics dashboard. |
| Tenants | `/admin/tenants`, `/admin/tenants/:tenantId` | List and inspect tenants; explicitly create a tenant with its first environment; suspend, resume, restore, or delete through the server's lifecycle rules. The console does not edit tenant properties. |
| Environments | `/admin/environments`, `/admin/environments/:environmentId` | List, inspect, create, and delete environments in the active tenant. Choose development, staging, or production and view the resolved guardrails. Production creation requires a custom domain. Guardrails are read-only here. |
| Clients | `/admin/clients` | List and create DCR registration policies; issue initial access tokens; look up a registered client by ID and verify its quarantine status; choose server-provided ID-token signing recommendations; set or clear a machine grant scope allowlist; manage a client's service-account keys. |
| Users | `/admin/users`, `/admin/users/:userId` | List, inspect, and create identities; merge-patch profile claims; change lifecycle state or schedule offboarding; link or unlink an external ID; revoke the user's sessions; delete; create, rotate, revoke, and inspect personal access tokens. |
| Connectors | `/admin/connectors`, `/admin/connectors/:connectorId` | List, inspect, create, replace, and delete federation connector definitions; inspect derived capabilities and this node's live connector health. |
| Organizations | `/admin/organizations`, `/admin/organizations/:organizationId` | List, create, inspect, enable, disable, and delete organizations; manage memberships, default role, organization API keys, roles, role permissions, and group hierarchy. |
| Permissions | `/admin/permissions` | Define the environment's permission vocabulary, inspect entries, relabel display names, delete permissions, and enable or disable permission claims for existing resource servers. |
| Invitations | `/admin/invitations` | List by pending, accepted, or revoked state; create password or passkey invitations; resend pending invitations with a fresh single-use token; revoke. |
| Diagnostics | `/admin/diagnostics` | Inspect client authentication failures, policy traces, operational warnings, existing flows, and side-effect-free flow dry runs. |

Unknown browser routes display a page with a link back to Overview. Missing
static assets return a server 404 rather than the console document.

### Client registration and machine identities

The Clients page focuses on Dynamic Client Registration (DCR). It does not offer
a generic complete client list or a direct create/update/delete client form.
Registration policies contain server-validated JSON primitive arrays. An initial
access token references a policy chain and lets a registrant call the issuer's
registration endpoint subject to that chain, the configured DCR mode and quota,
and quarantine rules. Registration must be enabled on the issuer for that flow.

Use the registered-client lookup to inspect verification status and explicitly
verify a quarantined client. The token signing dialog retrieves recommendations
from the server for the chosen verifier, then pins the recommended signing
algorithm to the supplied client ID. The machine grant scope allowlist limits
what a machine may request; it does not grant application permissions or make
every listed scope issuable.

A service account is created lazily at a client's first machine
client-credentials issuance. The machine key lookup distinguishes a missing
client, a registered client with no service account yet, and an existing service
account whose keys can be managed. The console does not precreate that principal.

### User profile and lifecycle

The profile editor accepts a JSON object as an RFC 7396 merge patch of the user's
claims. Supply only the fields you intend to change. For example, updating a
display name can use:

```json
{"name":"Alex Morgan"}
```

The access panel exposes `active`, `blocked`, `disabled`,
`pending_verification`, `scheduled_offboarding`, and `waitlisted`. Scheduled
offboarding needs a deadline. The server determines the allowed transitions and
their effect on authentication and sessions; see [user lifecycle](design/USER-LIFECYCLE.md).
Creating an identity alone does not configure a password or passkey. Use the
appropriate invitation, authentication, or management credential operation.

### Connector definitions and health

Connector creation and replacement accept a declarative JSON object validated
by the server against the [connector schema](connector-schema.json). Use the
configured secret store references for upstream credentials. Replacement is a
full-definition PUT, not a merge patch: supply every setting you intend to
retain. The capability panels report login, refresh, group, logout propagation,
and email-verification trust support from the server's derived matrix. Health
reports counters, recent errors, and timestamps for the serving node.

### Organizations, role provenance, and permissions

Open an organization to work with these panels:

- **Members:** add an existing user by ID, remove a membership, and open its
  roles. The membership's stored state remains visible.
- **Default role:** designate one organization role for all active members.
  Designating another role moves the designation. Clearing it deletes neither
  the role nor its direct/group grants. If it is absent from a partial role
  page, the console reports the uncertainty instead of claiming no default.
- **API keys:** inspect, create, rotate, and revoke organization credentials.
- **Roles:** create roles with stable slugs, rename their display names, delete
  them, and attach or detach permission IDs from the environment vocabulary.
- **Groups:** create and rename groups, move a group within the hierarchy,
  delete it, add or remove organization memberships, and grant or withdraw group
  roles. The group tree supports keyboard navigation and reports partial data.

Member roles distinguish direct grants from effective role paths. An effective
role may come from a direct grant, group inheritance, the default role, or a
time-boxed grant; the console preserves separate provenance rows when several
paths reach the same role. Withdrawing a direct grant can leave access through
another path. Time-boxed provenance is displayed here; this console does not
include the access-request approval workflow that produces those grants.

The effective view also shows the resolved permission union and its element-count
budget. That is an advisory view, not proof that the next token will contain the
claim: audience opt-in, token format, and other mint-time size limits also apply.
Read [organization hierarchy and entitlements](design/ORG-HIERARCHY-AND-ENTITLEMENTS.md)
for inheritance and claim rules.

Permission slugs and kinds are immutable; only display names can be relabeled.
The Permissions page can toggle the permission claim on an existing resource
server, but cannot register one or change its token format. Opaque resource
tokens cannot opt in. Removing a role mapping, deleting a permission, or
disabling claim emission changes subsequent token issuance; it does not revoke
access tokens that have already been issued.

### One-time credentials and invitations

New or rotated organization keys, personal access tokens, service-account keys,
DCR initial access tokens, and invitation tokens are displayed once. Copy the
value and deliver or store it through your intended secret handling process
before leaving the page, switching context, or reloading. The browser holds the
output in memory; list responses do not recover the raw credential. An idempotent
replay may return metadata without the original secret. Revoked key rows remain
visible for investigation.

Invitation creation can select password or passkey enrollment and an expiry.
Resend replaces the old token with a fresh one and expiry; revoke makes the token
unredeemable. The console exposes the one-time token for the operator to deliver
through the intended channel; it does not provide an email composer or automatic
delivery confirmation.

### Diagnostics and flow inspection

Client authentication records show the specific failure reason, client and
authentication method, assertion key ID/algorithm, derived clock skew, and time.
The public token endpoint continues to return an opaque `invalid_client`. Apply
the diagnostics filters explicitly; when results are truncated, narrow the client
or time window.

Policy traces show recorded rule evaluations. Operational warnings are grouped
by kind and computed from connector health, recent token-size events, and
permission-budget verdicts. Connector health is local to the serving node: a
connector not exercised there can be `unknown`, which is not an outage verdict
for the entire deployment.

The flow inspector can observe an existing flow by ID without advancing it, or
dry-run login, registration, recovery, or federation contexts. Dry runs evaluate
the real step-up and risk policies with writes disabled. They do not authenticate
a user, mint a token, send a message, or create a persistent flow. See
[headless flows](FLOWS.md) for the flow object and [configuration](CONFIG.md) for
diagnostics recording and retention settings.

## Authority, feature gates, and errors

Today the browser's OIDC subject allowlist resolves a signed-in administrator to
the **operator** plane. It does not bind console users to the management API's
delegated `help_desk`, `org_admin`, or `read_only` personas. Those personas apply
to scoped management keys, with independent permission grants and optional
organization confinement. Application roles and permission slugs are a separate
authorization vocabulary; granting an application permission does not grant
console administration.

The management API's closed permission vocabulary is:

| Grant | Authority within the credential's scope |
| --- | --- |
| `management.read` | Read management resources, including identity export. |
| `management.write_config` | Write configuration, connections, client settings, and policies. |
| `management.write_users` | Manage identities and their credentials/factors. |
| `management.write_organizations` | Manage organizations, memberships, roles, groups, and permissions. |
| `management.write_credentials` | Manage management credentials themselves. |
| `management.impersonate` | Authorize impersonation; no built-in delegated persona grants it automatically. |

`help_desk` combines read with user management, `org_admin` combines read with
organization management, and `read_only` grants read alone. Organization
confinement is a separate property of a management credential, not an automatic
property of the `org_admin` persona. Operator credentials have broader reach.
See [management authentication and authorization](../crates/ironauth-admin/src/auth.rs)
for the enforced vocabulary and scope rules.

The sidebar and action controls are not a per-permission entitlement map. The
server enforces credential scope, management permissions, organization
confinement, lifecycle restrictions, feature flags, and guardrails on each
operation. A visible control does not imply that its operation is enabled or
authorized. API-only facilities such as config promotion, schema extensions,
SCIM administration, signing-key rotation, logs/exports, webhooks, and delegated
management credentials require the documented API or its other clients.

Management errors display the API's `error` and `message` verbatim, with scope,
guardrail, and authentication freshness details when supplied. Bodyless or
unreadable failures use a fallback error instead of being treated as empty
success. Keep those details when investigating a failed integration; do not
replace a server refusal by changing the browser's local scope.

## Keyboard and narrow-screen behavior

The console has a skip-to-content link, labeled fields and controls, visible
keyboard focus, current-page navigation, and page titles that follow the active
section. Narrow screens use a navigation toggle; Escape closes the menu and
returns focus to that toggle. Route changes scroll to the top and focus the main
content. Creation dialogs use the browser's native modal dialog behavior to keep
the background inert and contain focus. These describe implemented behaviors,
not an accessibility certification.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `/admin/` returns 404 | `admin_spa.enabled` and whether this request reaches the public listener. |
| The sign-in control is disabled | Served admin issuer and public client ID metadata. In embedded deployments, OIDC plus the issuer tenant/environment and management audience must be configured for runtime injection. |
| Discovery or callback fails | Issuer reachability, provisioned public client, exact `/admin/` callback origin, PKCE support, and reverse-proxy public URL configuration. |
| Code exchange fails after successful issuer sign-in | This console client's explicit bearer-token allowance. Public clients require DPoP by default, but the current SPA does not send proofs. Also check the exact client/callback and resource registration. |
| Login succeeds but management requests fail | Exact audience, `ironauth.manage` scope, administrator `sub` allowlist, and management-plane startup. The proxy adds no operator credential. |
| `/admin/api/...` returns 404 | A configured OIDC bridge and a successfully mounted management plane, including the bootstrap token and control database connection. |
| A resource is missing from a filtered list | Active scope and the initial-page/local-filter boundary. Query subsequent API cursor pages for a complete inventory. |
| Connector health is `unknown` | Whether that connector has been exercised on the node serving the request. |
| A one-time token is no longer visible | Raw credentials cannot be recovered from lists. Use the relevant rotation or resend operation if you need a replacement. |
