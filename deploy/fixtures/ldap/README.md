# The directory fixture (issue #142)

`ldap_live` and `ldap_live_pass` run against a REAL `slapd`, because the properties they cover
are properties of the LDAP PROTOCOL and a hand-written fake asserting them only asserts a belief
about the protocol. This directory is what those tests run against, in CI and by hand.

## What each piece is for

Most of the seed is load-bearing, and the two entries that are not are named as such rather than
left to look like coverage:

| Fixture | What needs it |
| --- | --- |
| five `inetOrgPerson` under `ou=People` | the paged search, and the whole-pass provisioning count |
| `cn=svc` with `size.soft=2 size.prtotal=unlimited` | makes an UNPAGED search of those five fail with `sizeLimitExceeded` while a paged one succeeds. Without the asymmetry, a client that never sends the paging control passes the paging test |
| the ACL granting `cn=svc` read | without it the bind succeeds and every search fails; see `02-config.ldif` |
| `all-staff` <-> `engineering`, each a member of the other | a real membership cycle. The walk must terminate and report the revisit, and a fixture without a cycle cannot tell a cycle detector from its absence |
| `jpegPhoto` on `grace`, sixteen non-UTF-8 bytes | that a REAL server returns a non-text attribute the way the mapper expects. The mapper's own handling of octet strings is covered without a server, by `ldap_mapping`; what this adds is that `slapd` and that code agree |
| `ou=Referrals` holding a referral | a search that returns a continuation reference. The client must refuse to treat a partial answer as a complete one |
| `mail` on each person | NOT asserted by any test today. It is here because a person with no mail attribute is not a realistic directory entry, and the attribute-list derivation is exercised against `uid` and `cn` instead |
| `uid=here,ou=Referrals` | NOT asserted by any test today. `search_all` returns the referral as an error before any caller sees an entry list, so the person beside it is never read. Kept because a referral OU containing nothing but a referral is not a shape a real directory has |
| `uid=ada.lovelace` whose `uid` differs from its `cn` | that the login is the mapped attribute rather than the display name. Note the assertion that actually pins this is on GRACE (`mapped.username == "grace"` against cn "Grace Hopper"); ada is a second instance of the same shape, not separately asserted |

## Running the tests against it

CI does this in the `ldap-live` job. By hand, with any container runtime, and note that BOTH
servers are needed: one property under test is that a StartTLS upgrade a server DECLINES does not
fall back to binding in the clear, and only a server built with no TLS at all answers that
request with `protocolError`. `osixia/openldap:1.5.0` defaults `LDAP_TLS` to true, so the second
server needs it switched off explicitly.

```
docker run -d --name ironauth-ldap -p 3389:389 \
  -e LDAP_ORGANISATION=Example -e LDAP_DOMAIN=example.test \
  -e LDAP_ADMIN_PASSWORD=adminpw osixia/openldap:1.5.0
docker run -d --name ironauth-ldap-plain -p 3390:389 \
  -e LDAP_ORGANISATION=Example -e LDAP_DOMAIN=example.test \
  -e LDAP_ADMIN_PASSWORD=adminpw -e LDAP_TLS=false osixia/openldap:1.5.0

# Wait for both to accept a bind, then seed the data and the cn=config half.
ldapadd -x -H ldap://127.0.0.1:3389 -D "cn=admin,dc=example,dc=test" -w adminpw \
  -f deploy/fixtures/ldap/01-seed.ldif
docker cp deploy/fixtures/ldap/02-config.ldif ironauth-ldap:/tmp/02-config.ldif
docker exec ironauth-ldap ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/02-config.ldif

export IRONAUTH_LDAP_URL=ldap://127.0.0.1:3389
export IRONAUTH_LDAP_PLAINTEXT_URL=ldap://127.0.0.1:3390
cargo test -p ironauth-admin --all-features --test ldap_live -- --ignored
bash scripts/with-test-db.sh cargo test -p ironauth-admin --all-features \
  --test ldap_live_pass -- --ignored
```

Without `IRONAUTH_LDAP_PLAINTEXT_URL` the StartTLS test fails on its first line, so the suite is
6/7 rather than 7/7.

## What is NOT here

The Samba-AD half of #142's first criterion. Active Directory's `objectGUID` is sixteen raw bytes
in a mixed-endian rendering that OpenLDAP has no equivalent of; the mapper handles it and is
covered by `ldap_mapping`'s unit fixtures, but no live server exercises it. Stated rather than
implied: a reader should not conclude from a green `ldap-live` job that AD is exercised.
