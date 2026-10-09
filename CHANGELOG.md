# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Images are built from tagged commits outside this repository, so deployments have a readable
version to pin.

## [Unreleased]

### Added

- Test suite (`node --test`) driving the published entrypoint over HTTP against a stub
  signing-service: the full offer → token → nonce → proof → credential round-trip, the coordinator
  token guard, startup validation and the TTL store. Needs no Docker and no network.
- GitHub Actions workflow running the suite on Node 20, 22 and 24, and building the image, so a
  `Dockerfile` that cannot build from a clean clone fails the pull request.
- `docker-compose.yml` bringing up this service together with the `signing-service` it delegates to,
  with no sibling checkouts required.
- `HEALTHCHECK` and a `GET /healthz` endpoint for it and for compose's `service_healthy` condition.
- `package-lock.json`, which `npm ci` in the `Dockerfile` requires.
- `CONTRIBUTING.md`, `SECURITY.md`, `.nvmrc`, `.editorconfig` and a Dependabot configuration.

### Changed

- `/credential` now accepts only the proof signing algorithms the matching credential configuration
  advertises in `proof_signing_alg_values_supported`, falling back to an asymmetric-only allowlist.
  Previously any algorithm was accepted, including symmetric ones: a wallet could sign the
  proof-of-possession JWT with an `HS256` key it invented and embedded in the JWT's own header, which
  made the proof check pass without the wallet possessing anything.
- The `COORDINATOR_TOKEN` check now compares digests in constant time instead of with `!==`.
- The container runs as the `node` user.
- README documents how the component fits into the wider system, and what deploying it involves.

### Removed

- The build-and-push workflow. Images are built and published outside this repository instead, so
  that registry credentials are not configured from a public one.

## [0.0.1]

- Initial OID4VCI 1.0 pre-authorized-code issuer.
