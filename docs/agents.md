# Agent principals

An **agent** is an autonomous process an operator registers inside one organization to act for
one named person. It is not a service account with a label: it carries its own identity into
every token it obtains, and every token it obtains names the human it acts for.

Registering one requires three things, and the third is what makes an agent an agent:

| | |
|---|---|
| An **organization** | the agent exists inside it, and is listed, inspected and revoked there |
| A **linked user** | the person whose authority it exercises. An agent acting for nobody is unattributable, so this is required |
| A **declared tool set** | the complete set of scopes it may ask for. Enforced at issuance, not advised |

A registered agent is optionally **bound to an OAuth client**, which is the door it obtains
tokens through. An unbound agent is listable, auditable and revocable; it simply has no way to
ask for a token.

## What a token carries

A token issued to an agent carries three claims beyond an ordinary machine token:

| Claim | |
|---|---|
| `agent_id` | the agent principal |
| `agent_linked_user` | the person it acts for |
| `agent_organization` | the organization it acts inside |

All three are **issuer-set and protected**. A client cannot self-assert them through a custom
claim, a claims mapping, or a token hook: each of those paths refuses the names outright, and a
test enumerates the protected set so a name added later cannot slip past unprobed.

## Per-tool enforcement

Every scope token in a request must be one the agent declared. A request naming anything
outside the set is refused with `invalid_scope`, and the refusal is **audited before it is
returned**, naming every undeclared tool rather than the first, so a caller fixes the request
once instead of being sent round the loop one tool at a time.

Membership is exact. `files` does not grant `files.delete`, because a set that matched by prefix
would be a widening rather than a bound.

A request naming **no** scope is not a widening and passes. The token then carries no tool at
all, which is the correct answer to asking for none.

## Revocation, stated plainly

Revoking an agent does two things, in one transaction:

1. **New issuance stops immediately.** Every machine-token door consults the agent's state, and
   a suspended or revoked agent obtains nothing. There is no window here at all.
2. **The grants behind its outstanding tokens are revoked.** An access token derives its active
   state from `grants.revoked_at`, so every token already issued to the agent resolves as
   inactive at introspection and at UserInfo, and any refresh chain stops.

   Scoped to the agent's grants, not the client's. The cascade constrains both the client and
   the client's service-account subject, so a person who happens to hold a grant on the same
   client is untouched: revoking an agent is not revoking a client.

What revocation **cannot** reach is a resource server that verifies an `at+jwt` signature
without asking IronAuth anything. That token is self-contained and stays verifiable until its
`exp`. So:

> **The revocation window is exactly `oidc.access_token_ttl_secs`, and only for a resource
> server that does not introspect.**

At the default `access_token_ttl_secs: 300` that is a 300-second worst case between an operator
revoking an agent and the last token it holds ceasing to verify at a non-introspecting resource
server. Every IronAuth-side check is immediate.

| | seconds |
|---|---|
| Default `access_token_ttl_secs` | 300 |
| Worst-case window, non-introspecting resource server | 300 |
| Worst-case window, introspecting resource server | 0 |

A deployment that needs a smaller number lowers `access_token_ttl_secs` or requires
introspection at its resource servers. This is the whole trade, and it is the same one
`docs/session-tokenizer.md` describes for tokenized sessions: a credential verified with no
database call cannot be recalled, only outlived.

**Suspension is not revocation.** A suspended agent obtains no new tokens and stays listable and
auditable, and its outstanding grants are left alone: suspension is a pause an operator expects
to undo, and killing the grants would make every resumption a re-issuance. Revocation is
terminal and the store refuses to move an agent out of it.

## What is audited

| Action | |
|---|---|
| `agent.register` | an agent was created |
| `agent.state.set` | its lifecycle state changed, with which state on the row |
| `agent_token.issue` | it obtained a token |
| `agent_token.deny` | it was refused, with the reason |

The first two are account-change events; the last two are authentication events, and they are
deliberately in different OCSF streams because they answer different questions.

Every one of the four is attributed to the agent's **organization** and to its **linked user**,
so a per-organization SIEM stream delivers them and a correlation by person finds them.

One consequence worth stating, because it is a disclosure rather than a bug in the plumbing:
an agent's linked user is validated to exist in the environment, not to be a member of the
organization the agent belongs to. An operator who links a user from organization B to an
agent in organization A puts B's user id on A's stream. Requiring membership at registration
is the fix, and it is a behaviour change to an already-shipped route rather than something
this attribution should paper over. The
organization and the subject are carried on the audit row and rendered into the shipped OCSF
event as typed `resources` entries; they are deliberately **not** part of what the audit chain
seals, because adding a field to that would invalidate every entry already sealed.
