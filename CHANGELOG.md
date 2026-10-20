# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Images are built from tagged commits outside this repository, so deployments have a readable
version to pin.

## [Unreleased]

### Added

- `GET /.well-known/did.json`: a `did:web` DID Document for the credential issuer's host, listing the
  credential-signing keys (the JWKS keys, `kid` as the fragment). Credentials keep the HTTPS URL as
  `iss`. UniMe requires the document from every OID4VCI issuer.
- README "Interoperability": the robustness principle and the list of tolerated wallet behaviour.

### Changed

- Proof JWTs may name the holder key as a `did:jwk` DID URL in `kid` instead of a `jwk` header
  (OID4VCI 1.0 App. F.1, DIIP v5). The credential then carries `cnf.kid` (the DID URL) next to
  `cnf.jwk`. Other DID methods are refused with `invalid_proof`.
- A proof `aud` with or without a trailing slash matches the Credential Issuer Identifier.

### Fixed

- `/credential` accepts the `Bearer` scheme in any case (RFC 7235). `/token` returns
  `token_type: "bearer"`, so a wallet that echoed it got a 401.

## [0.0.4] - 2026-10-18

### Added

- Selective disclosure for `dc+sd-jwt`: an offer may list top-level claim names in `disclosable`, and
  those claims are issued as SD-JWT disclosures (`_sd`, `_sd_alg: sha-256`) instead of plain claims.
  Without `disclosable` the credential is unchanged (`<jws>~`). The list is checked when the offer is
  created: unknown, repeated or always-disclosed claims (`vct`, `status`), or a `disclosable` for any
  other format, are rejected with 400.

## [0.0.3] - 2026-10-17

### Added

- OpenID Federation Entity Configuration at `/.well-known/openid-federation` (DIIP v5 and the OpenID
  Federation Wallet Architectures profile), switched on by `FEDERATION_ENTITY_METADATA`, with
  `FEDERATION_AUTHORITY_HINTS`, `FEDERATION_TRUST_MARKS` and `FEDERATION_ENTITY_CONFIGURATION_TTL`.
  It is signed with the SD-JWT key and needs `SD_JWT_ISSUER` to equal `CREDENTIAL_ISSUER`.
- `dc+sd-jwt` credentials carry `fed` (the Entity Identifier) when federation is on; `fed` is now a
  reserved claim that coordinators must not send.
- `vc+sd-jwt` credentials carry a `termsOfUse` entry of type `OpenIDFederation` when federation is on.
- `npm run federation:setup` (`scripts/federation-metadata.js`): asks for the entity metadata and prints
  or writes the `FEDERATION_*` lines, so nobody has to hand-write the JSON.

### Removed

- The Type Metadata route at the `vct` URL (`typeMetadata()`): the `vct` is hosted outside this service.

No new required variables: federation stays off until `FEDERATION_ENTITY_METADATA` is set.

## [0.0.2] - 2026-10-17

### Added

- Wallet credentials signed by this service itself with an ES256 key: IETF SD-JWT VC (`dc+sd-jwt`,
  with a `vct`) and VCDM 2.0 secured as `vc+sd-jwt`. No selective disclosure. The key is
  `SD_JWT_SIGNING_KEY`: a private JWK, `kms:<key ARN>` to sign with a non-exportable AWS KMS key, or
  `generate` for local development.
- Holder binding per credential configuration: one that lists `jwk` in
  `cryptographic_binding_methods_supported` gets the wallet's proof key as `cnf.jwk`.
- `GET /.well-known/jwt-vc-issuer`, publishing the signing key, and during a rotation the old ones
  from `SD_JWT_PREVIOUS_KEYS`.
- An optional `x5c` certificate chain in the SD-JWT header (`SD_JWT_X5C`), which Credo-based wallets
  such as Paradym need, and `scripts/self-signed-x5c.js` to make a stored self-signed certificate.
- `vct#integrity`, computed at startup from the configuration's `vct` and optionally pinned.
- The pre-1.0 singular `proof` is accepted as well as `proofs.jwt`.
- `LOG_REQUESTS=1` logs each request.
- `.env.example` tags every variable `# @env required|optional [secret]`; with `NODE_ENV=production`
  the service exits at startup naming all missing required variables.

### Changed

- **Deployments must set** `CREDENTIAL_ISSUER`, `CREDENTIAL_CONFIGURATIONS_SUPPORTED`,
  `SD_JWT_SIGNING_KEY` and `COORDINATOR_TOKEN`: the image refuses to start without them.
  `SIGNING_SERVICE_*` are needed only for `ldp_vc` configurations.
- `/credential` returns the OID4VCI 1.0 `{ "credentials": [{ "credential": ... }] }` with
  `Cache-Control: no-store`, instead of a top-level `credential`.
- Offer creation returns 400 for an unknown credential configuration, and for an SD-JWT credential
  whose issuer, `vct` or `validFrom` does not fit its configuration.
- The app is built by `createApp` in `src/app.js`; `index.js` only reads the environment and listens.

## [0.0.1]

- Initial OID4VCI 1.0 pre-authorized-code issuer.

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
