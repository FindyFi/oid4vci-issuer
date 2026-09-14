# oid4vci-issuer

A minimal [OID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
(OpenID for Verifiable Credential Issuance, final spec, 16 September 2025)
issuer service, implementing the pre-authorized-code flow only. It is
deliberately content-agnostic: a coordinator (your own backend, or
`digitalcredentials/issuer-coordinator` / `workflow-coordinator`) hands it an
already-built, unsigned Verifiable Credential; this service runs the
offer/token/nonce/proof protocol dance with a wallet, then delegates the
actual cryptographic signing to a
[`digitalcredentials/signing-service`](https://github.com/digitalcredentials/signing-service)
instance. It never inspects credential content itself, so it works for any
credential type/format signing-service can sign.

Run it the same way you'd run `signing-service` alongside a coordinator: as
its own process/container, not imported as a library.

## Configuration

See `.env.example`. Required: `CREDENTIAL_ISSUER` (this service's own public
HTTPS base URL), `CREDENTIAL_CONFIGURATIONS_SUPPORTED` (JSON — each entry
should declare `proof_types_supported`, since that's what makes 1.0 require a
proof, and therefore the Nonce Endpoint, for that credential type), and
`SIGNING_SERVICE_URL`/`SIGNING_SERVICE_INSTANCE` (where to forward signing).
Set `COORDINATOR_TOKEN` in anything beyond local dev.

## Endpoints

Coordinator-facing (should sit behind network isolation and/or `COORDINATOR_TOKEN`):

- `POST /instance/:tenant/offers` — body `{ credentialConfigurationId, unsignedCredential, txCode? }`.
  Returns `{ preAuthorizedCode, txCode, offerUri, expiresIn }`. `offerUri` is
  an `openid-credential-offer://` link, ready to render as a QR code or deep
  link.

Wallet-facing (public):

- `GET /.well-known/openid-credential-issuer` — issuer metadata, including
  `nonce_endpoint`.
- `GET /instance/:tenant/offers/:code` — the hosted `credential_offer` JSON.
- `GET /instance/:tenant/offers/:code/status` — `{ used: boolean }`, for a
  coordinator that wants to poll for pickup.
- `POST /token` — pre-authorized_code grant (form-encoded, standard OAuth2
  token endpoint shape). Per 1.0 (unlike some pre-1.0 drafts), the response
  does **not** include `c_nonce` — get that from `/nonce` instead.
- `POST /nonce` — Section 7. Unauthenticated (not a protected resource, per
  spec), empty request body, returns `{ c_nonce }`.
- `POST /credential` — body must include a matching `credential_configuration_id`
  and a `proofs` object (plural, per Section 8.2 — `{"proofs":{"jwt":["<jwt>"]}}`,
  not a singular `proof`). This service only supports exactly one proof per
  request (one offer = one credential instance, no batch issuance). Verifies
  the proof JWT (signature, `aud`, `typ: openid4vci-proof+jwt`) and that its
  `nonce` claim is a real, unused value from `/nonce`, calls signing-service,
  returns `{ credential }` (singular, for the single-credential case this
  service supports).

## Design notes

- **Bearer credential, no holder binding**: the proof JWT's signature/nonce/
  audience are verified (required by spec), but its key is not used to bind
  `credentialSubject.id`. A future opt-in binding step would use the
  `header.jwk` already available from `src/proof.js`'s `verifyProof`.
- **Nonce Endpoint is unauthenticated by design** (Section 7: "not a
  protected resource"), and therefore decoupled from any specific access
  token — `src/nonce.js` stores issued nonces independently of `/token`'s
  bookkeeping, and `/credential` just checks that the proof's `nonce` claim
  is a real, unused value, not that it was issued to *this* access token.
- **In-memory store**: offers/tokens/nonces live in an in-memory `Map` with
  TTL (`src/store.js`), fine for a single process; swap in a Redis-backed
  implementation of the same `{ get, set, delete }` shape if this needs to
  run multi-process.
