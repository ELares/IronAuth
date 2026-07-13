# Changelogs

IronAuth artifacts are versioned and released independently; there is no
repo-wide changelog. Each artifact keeps its own changelog next to its
manifest:

- [crates/ironauth/CHANGELOG.md](crates/ironauth/CHANGELOG.md): the server binary
- [crates/ironauth-env/CHANGELOG.md](crates/ironauth-env/CHANGELOG.md): the environment seam library
- [crates/ironauth-config/CHANGELOG.md](crates/ironauth-config/CHANGELOG.md): the strict configuration layer library
- [crates/ironauth-server/CHANGELOG.md](crates/ironauth-server/CHANGELOG.md): the HTTP server skeleton library
- [crates/ironauth-store/CHANGELOG.md](crates/ironauth-store/CHANGELOG.md): the persistence and tenant isolation layer library
- [crates/ironauth-fetch/CHANGELOG.md](crates/ironauth-fetch/CHANGELOG.md): the SSRF-hardened outbound fetcher library
- [crates/ironauth-jose/CHANGELOG.md](crates/ironauth-jose/CHANGELOG.md): the hardened JOSE verification core library
- [crates/ironauth-admin/CHANGELOG.md](crates/ironauth-admin/CHANGELOG.md): the OpenAPI-first management API library

The authoritative artifact list with versions is the generated
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md). The release process and the
security advisory format are defined in [docs/RELEASING.md](docs/RELEASING.md).
