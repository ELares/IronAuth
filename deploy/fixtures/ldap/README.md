# The directory fixture (issue #142)

`ldap_live` and `ldap_live_pass` run against a REAL `slapd`, because the properties they cover
are properties of the LDAP PROTOCOL and a hand-written fake asserting them only asserts a belief
about the protocol. This directory is what those tests run against, in CI and by hand.

## Why each piece is here

Nothing in `01-seed.ldif` is decoration. Every entry exists because a test cannot fail without it:

| Fixture | The test that needs it |
| --- | --- |
| five `inetOrgPerson` under `ou=People` | the paged search, and the whole-pass provisioning count |
| `cn=svc` with `size.soft=2 size.prtotal=unlimited` | makes an UNPAGED search of those five fail with `sizeLimitExceeded` while a paged one succeeds. Without the asymmetry, a client that never sends the paging control passes the paging test |
| `all-staff` <-> `engineering`, each a member of the other | a real membership cycle. The walk must terminate and report the revisit, and a fixture without a cycle cannot tell a cycle detector from its absence |
| `jpegPhoto` on `grace`, sixteen non-UTF-8 bytes | an attribute that is NOT text. The mapper's octet-string path is unreachable without one |
| `ou=Referrals` holding a referral to another server | a search that returns a continuation reference. The client must refuse to treat a partial answer as a complete one |
| `uid=ada.lovelace` whose `uid` differs from its `cn` | the login is the mapped attribute, not the display name |

## Running the tests against it

CI does this in the `ldap-live` job. By hand, with any container runtime:

```
docker run -d --name ironauth-ldap -p 3389:389 \
  -e LDAP_ORGANISATION=Example -e LDAP_DOMAIN=example.test \
  -e LDAP_ADMIN_PASSWORD=adminpw \
  -v "$PWD/deploy/fixtures/ldap/01-seed.ldif":/container/service/slapd/assets/config/bootstrap/ldif/custom/01-seed.ldif:ro \
  osixia/openldap:1.5.0 --copy-service
# then apply the search limits, which are cn=config rather than data:
docker exec -i ironauth-ldap ldapmodify -Y EXTERNAL -H ldapi:/// \
  < deploy/fixtures/ldap/02-config.ldif

export IRONAUTH_LDAP_URL=ldap://127.0.0.1:3389
cargo test -p ironauth-admin --all-features --test ldap_live -- --ignored
bash scripts/with-test-db.sh cargo test -p ironauth-admin --all-features \
  --test ldap_live_pass -- --ignored
```

`IRONAUTH_LDAP_PLAINTEXT_URL` is a SECOND server built with TLS switched off, which answers the
`StartTLS` extended request with `protocolError`. The image serves plaintext on 389 without TLS
material unless it is given some, so a second container with no certificate is that server.

## What is NOT here

The Samba-AD half of #142's first criterion. Active Directory's `objectGUID` is sixteen raw bytes
in a mixed-endian rendering that OpenLDAP has no equivalent of, and the mapper's handling of it is
covered by unit fixtures rather than by a live server. Stated rather than implied: a reader
should not conclude from a green `ldap-live` job that AD is exercised.
