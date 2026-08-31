# Skill: migrate to IronAuth from an incumbent

Use this when a user is moving from Auth0, Okta, Cognito, Keycloak, or a homegrown identity
system.

## Before writing any code

**Search the docs first.** Call `search_docs`. Migration guidance in particular ages badly,
because it describes two moving products at once.

## Step 1: read the exit guide, in both directions

`docs/exit-guide.md` documents how to get OUT of IronAuth. Read it early and show it to the
user: a vendor whose exit path is documented is making a different promise from one whose is
not, and a user weighing a migration is entitled to know how the next one would go.

## Step 2: users and their password hashes

IronAuth imports **foreign password hashes** and rehashes them to Argon2id on the user's first
successful login. That is the property that makes a migration invisible to users: no forced
reset, no "please choose a new password" email.

Search for the import surface rather than guessing at it, and check which hash formats are
supported before promising the user a silent cutover.

## Step 3: what does NOT come across

Be explicit with the user, early:

- **Sessions do not migrate.** Everyone signs in again once, on whatever schedule you cut over.
- **Refresh tokens do not migrate.** They are the incumbent's credentials.
- **Anything the incumbent does that IronAuth deliberately will not** -- read
  `docs/WILL-NOT-IMPLEMENT.md` and check it against the user's list *before* planning the
  migration, not after. A feature the product has decided against is not a roadmap item.

## Step 4: the client and flow shapes

IronAuth is standards-first, so an incumbent's standard flows port directly and its proprietary
extensions do not. Map each of the user's flows to an OAuth/OIDC one; where an incumbent has a
non-standard endpoint, find the standard equivalent rather than looking for a matching
non-standard one.

## Step 5: cut over per environment

Migrate a staging environment first and run the user's real login flows against it. IronAuth
issuers are per environment, so a token from staging is not valid in production -- which is a
safety property during a migration and also the most common source of "wrong issuer" errors
while one is in progress.

## What to tell the user

- everyone signs in again once;
- passwords carry over silently and rehash on first login;
- which of their incumbent's features have a standard equivalent and which do not;
- the exit path out of IronAuth, because they just paid for not knowing one.
