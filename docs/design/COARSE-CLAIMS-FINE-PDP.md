# Coarse claims plus a fine PDP

The blessed authorization architecture for IronAuth (issue #100), and the explicit
non-goal that shapes it.

## The non-goal, first

IronAuth does not ship an in-core Zanzibar / ReBAC engine, and will not. That is a
decision with evidence behind it rather than a gap in the roadmap. OpenFGA spent 2026
fixing correctness in a rewrite of its own check algorithm, and Ory Keto never shipped
consistency tokens after six years. Relationship-based authorization is a product, not a
feature, and an identity provider that grows one badly is worse than one that does not
grow one at all: the failures are silent grants.

So IronAuth answers what it already indexes, says so precisely, and offers seams to a
real FGA for everything else.

## The three layers, and which question each answers

| Layer | Answers | Cost per check | Freshness |
|---|---|---|---|
| Token claims | "what does this subject broadly hold?" | zero, it is in the token | as of issuance |
| The AuthZEN PDP | "does this subject hold permission P in organization O?" | one call to IronAuth | live |
| An external FGA | "can this subject edit THIS document?" | one call to the FGA | live |

The first two are IronAuth's. The third is not, and the seams below are how it joins.

**Coarse claims** carry what almost every request needs: the organization, the roles, the
budgeted permission set. They are free to check because they are already in the token, and
they are correct as of issuance, which is the right tradeoff for a permission set that
changes on the timescale of an admin action.

**A fine PDP** answers the rest, per request, live. Use it when the answer depends on the
specific object (this document, this ticket, this row), when it changes faster than a token
lifetime, or when the permission set is too large to carry.

## The overflow path, and why it exists

The permission claim has a budget (issue #98). A subject whose effective permission set
does not fit does not get a truncated claim, because a truncated authorization claim is
the worst possible artifact: it looks authoritative and is wrong in the direction of
under-granting, which surfaces as intermittent access failures nobody can reproduce.

Instead the mint applies `token_claims.permission_claim_overflow`. Set it to
`pdp_required`, and an over-budget subject receives a token that says the permission set
did not fit, and the relying party asks the AuthZEN PDP for the specific permission it
cares about. Force-PDP is the safe direction: a check that costs a round trip is worse
than a free one and far better than a wrong one.

## The two seams to an external FGA

### 1. Claims enrichment, at issuance

`[oidc.claims_enrichment]` calls an external PDP or FGA during token issuance and merges
allowlisted claims into the ID token. Use it when the FGA's answer is stable enough to
carry for a token lifetime and small enough to fit.

It only ever ADDS, it can only contribute names the operator allowlisted, and it can never
contribute a claim IronAuth mints itself. It fails OPEN: an FGA outage costs the
deployment some claims and never a login, because these claims are additive and their
absence is fewer permissions rather than more. A relying party that requires an enriched
claim to authorize still refuses without it.

Do not use it for per-object decisions. A claim is a fact about the subject; "can edit
document 12345" is a fact about a pair, and putting it in a token means minting a token
per object.

### 2. The identity-fact feed, for tuple sync

An FGA needs to know who exists, who is a member of what, and who holds which role. The
wrong way to learn that is to scrape IronAuth's database, which couples a second system to
a schema it does not own and drifts silently.

The right way is `ironauth_store::identity_fact`: a declared contract of the facts the
identity model emits, with their ordering rule and their translation into tuples. Tuple
sync is a CONSUMER of a declared feed rather than a scraper.

The contract defines six facts: `user_created`, `user_deleted`, `membership_added`,
`membership_removed`, `role_assigned`, `role_unassigned`. `docs/design/identity-facts.golden.json`
is the wire form, committed, and a test fails if the code and the file disagree, so a
consumer in another language can be written against the file.

Two properties are worth reading before writing a consumer:

**Ordering is per subject, not global.** Facts about one user arrive in the order they
became true; facts about different users have no relative order. `IdentityFact::ordering_group`
is what a producer passes to the outbox's ordering group. A consumer that assumed a global
order would serialise the whole feed behind its slowest subject for no correctness gain.

**A delete is a CASCADE.** `user_deleted` and `membership_removed` remove the role tuples
underneath them, and are not followed by a per-role removal. `TupleChange::DeleteAllFor`
exists so a consumer cannot apply a finite list and believe it is done.

The ordered events API that CARRIES this feed is M11's; issue #100 defines only what it
must carry.

## Choosing, in one paragraph

If the answer is the same for every object of a type and changes on the timescale of an
admin action, put it in a claim. If it depends on the object, ask a PDP. If it depends on
a relationship graph IronAuth does not model, run an FGA, sync it from the identity-fact
feed, and reach it either through the enrichment hook (stable, small) or directly from the
relying party (per object, live). If you are unsure, ask the PDP: a round trip is cheaper
than a wrong answer.
