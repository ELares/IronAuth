# AuthZEN agent tool profile (PROTOTYPE)

**Drafts:** the AuthZEN MCP tool-authorization profile, over OpenID AuthZEN Authorization API 1.0
**Feature flag:** `authzen-agent-profile`, EXPERIMENTAL
**Acknowledgment version:** `0.1.0-exp.1`
**Status:** prototype. It adds a subject type to an endpoint that is otherwise GA.

## What it does

Answers **may this agent call this tool** for an agent principal, on the AuthZEN PDP IronAuth
already serves:

```json
{
  "subject":  { "type": "agent", "id": "agp_..." },
  "resource": { "type": "tool",  "id": "deploy" },
  "action":   { "name": "call" },
  "context":  { "organization_id": "org_..." }
}
```

## The decision is an intersection, and that is the whole design

An agent is not a principal that holds permissions. It acts **for** a person, with a narrower set
of tools than that person could reach, so **both** halves must hold:

- the **agent** must declare the tool. `tool_scopes` is the operator's statement of what this
  machine may do, and a tool outside it is refused however privileged its human is.
- the **linked user** must hold the mapped permission, resolved through the same
  `effective_permissions` the token claims are built from. A second copy of that walk would be a
  second set of answers.

The permission is **`tool.{tool}.{action}`**, per tool, and that is a departure from the
`{resource.type}.{action.name}` join the other two subject types use. It has to be: this profile
requires `resource.type` to be `tool`, so that join is the constant `tool.{action}` for every
tool there is, and the human's half could not tell `deploy` from `destroy`. The first
implementation did exactly that, which made the intersection an intersection with a constant and
left `tool_scopes` as the only thing distinguishing tools. The tool is the resource **instance**,
so it belongs in the slug.

Either half alone is a different and wrong question. Checking only the declared set lets a
revoked human's agent keep working; checking only the human lets an agent call every tool its
person could.

**What "revoked human" means here.** The effective-permission closure filters deleted users and
inactive memberships and reads `users.state` nowhere, so the ceiling alone would leave a
**blocked** or **disabled** person's agent fully authorized. The profile therefore reads the
linked user and denies unless `can_authenticate()` -- the same predicate the login path fences
on. That admits `scheduled_offboarding`, which is correct: that person can still sign in, so
their agent may still act until the worker offboards them.

An agent that is **suspended or revoked** is denied while staying listable and auditable, which is
the split issue #130 criterion 5 draws at the token door. An agent belonging to **another
organization** is denied -- not reported missing: a PDP answers decisions, and
distinguishing "no such agent" from "not allowed" would tell a caller which agent ids are real.

## Where the tool name comes from

`resource.id`, with `resource.type` required to be `tool`. This is the **one** place on the
AuthZEN surface where `resource.id` is consulted; for a `user` or `service_account` subject it is
accepted and ignored, because IronAuth grants permissions per organization rather than per
instance. It is read here because the tool **is** the instance: `tool/deploy` and `tool/destroy`
are two resources rather than one resource with two ids, and a profile that ignored the id could
only ever answer "may this agent call *some* tool".

## Turning it on

```toml
[features]
authzen-agent-profile = { enabled = true, ack = "0.1.0-exp.1" }
```

**Why an `exp` counter here and a draft revision for attestation client auth.** That surface
implements one IETF draft whose wire format the IETF may change, so the revision is the thing
being acknowledged. This one composes IronAuth's **own** model -- an agent's declared tools, its
linked user's effective permissions -- onto the AuthZEN request shape, and the MCP profile draft
does not dictate that composition. What may break here is our decision, not theirs.

**Off is not "the endpoint refuses an agent."** With the flag unset, an `agent` subject draws the
same `subject_type_unsupported` refusal every unrecognised type has always drawn, byte for byte,
so a deployment that has not opted in cannot tell from the answer that the type means anything in
this build. That matters more here than for the other prototypes: this one widens a **live**
authorization surface rather than adding a dark one.

## What a graduation still needs

- **A tool name that is not a legal permission-slug segment can never be permitted.** The
  ceiling slug must pass the permission grammar (lowercase ASCII `[a-z0-9_-]` segments, at least
  two, at most 63 characters total), while `tool_scopes` is validated only for a non-empty array
  of non-blank strings. So `getWeather`, `fs:read`, `files/read` and `Deploy` all register fine
  and can never be granted: this answers `false` for ever and nothing says why. Fixing it means
  constraining `tool_scopes` on the GA agent surface, which a prototype does not get to change.
  It is the strongest limit here.
- **The action name is not constrained.** `tool.call` and `tool.anything-else` are equally valid
  slugs, so the profile answers for a permission an operator may never have intended to define.
  A graduation should either pin the action set or document the slug space explicitly.
- **No batch shortcut.** A PEP asking about twenty tools sends twenty entries and each resolves
  the human's permissions again. The batch endpoint already accepts them; what is missing is one
  resolution shared across a batch's entries.
- **The AARP direction is not started.** The Access Request and Approval Profile is the other half
  of the agent story the issue names, and the vault's approval flow (issue #132) is where it would
  compose.
