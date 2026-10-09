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

## How this fits together

In the Opintotodiste system this service is one of five moving parts:

```
  Koski (national study record registry)
      |  study records
      v
  opintotodiste ............. the coordinator: fetches Koski data, builds the
      |                       unsigned credential, owns the UI and database.
      |                       Depends on koski2openbadge as an npm package.
      |                         `-- koski2openbadge: Koski records -> Open
      |                             Badges 3.0 achievement data (a library,
      |                             no service, no deployment of its own)
      |  POST /instance/:tenant/offers  { unsignedCredential }
      v
  oid4vci-issuer (this repo) .. the wallet-facing protocol endpoint
      |
      |  POST /instance/:id/credentials/sign
      v
  signing-service ............ holds the signing keys
```

**This service does not depend on `koski2openbadge`,** and deliberately so.
`koski2openbadge` turns Finnish study records into Open Badges achievement
data; this service never looks inside the credential it is handed, which is
what lets it issue anything `signing-service` can sign rather than only
Finnish study credentials. The `koski2openbadge` dependency lives one layer
up, in
[`FindyFi/opintotodiste`](https://github.com/FindyFi/opintotodiste), which is
the component that builds credential content. If you are looking for how that
dependency is pinned and deployed, it is documented in that repository's
README — not here.

The practical consequence for anyone deploying: **this service can be
deployed, upgraded and rolled back on its own.** It shares no build inputs
with `koski2openbadge` or `opintotodiste`, and the only contracts it has to
keep are the two HTTP interfaces above.

## Configuration

See `.env.example`. Required: `CREDENTIAL_ISSUER` (this service's own public
HTTPS base URL), `CREDENTIAL_CONFIGURATIONS_SUPPORTED` (JSON — each entry
should declare `proof_types_supported`, since that's what makes 1.0 require a
proof, and therefore the Nonce Endpoint, for that credential type), and
`SIGNING_SERVICE_URL`/`SIGNING_SERVICE_INSTANCE` (where to forward signing).
Set `COORDINATOR_TOKEN` in anything beyond local dev.

The service refuses to start without `CREDENTIAL_ISSUER`, or with
unparseable `CREDENTIAL_CONFIGURATIONS_SUPPORTED`, rather than coming up in a
state that would fail later against a real wallet.

## Running locally

```sh
git clone https://github.com/FindyFi/oid4vci-issuer.git
cd oid4vci-issuer
docker compose up --build
```

That brings up this service on `http://localhost:4007` together with the
`signing-service` instance it delegates signing to. The compose stack is
self-contained — it needs no sibling checkouts and no credentials.

To run it directly instead:

```sh
npm install
cp .env.example .env   # then edit it
npm start
```

## Tests

```sh
npm test
```

The suite boots `index.js` in a child process against a stub signing-service
and drives a full offer → token → nonce → proof → credential round-trip, so
it covers the same wiring the container does. It needs nothing running
beforehand — no Docker, no network.

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
  the proof JWT (signature, `aud`, `typ: openid4vci-proof+jwt`, and that its
  algorithm is one the credential configuration advertises) and that its
  `nonce` claim is a real, unused value from `/nonce`, calls signing-service,
  returns `{ credential }` (singular, for the single-credential case this
  service supports).

Operational:

- `GET /healthz` — what the container `HEALTHCHECK` and compose's
  `service_healthy` condition wait on.

## Deployment

This repository **builds and tests only**. It does not publish images to any
registry, and it carries no environment-specific or infrastructure
configuration — everything the service needs at runtime comes from the
environment variables in [Configuration](#configuration).

Publishing is separate on purpose: the image is built from this
repository's `Dockerfile` and pushed to a registry elsewhere, and the
credentials for that live with it rather than here. Keeping registry access
out of a public repository is the point, so please do not add a push workflow
back into this one.

What that means in practice:

- **The `Dockerfile` here is the release artifact.** If it cannot build from
  a clean clone of `main`, no image can be published. CI builds it on every
  pull request for exactly that reason, and `package-lock.json` is committed
  because `npm ci` requires it.
- **Pin a tag, not `main`.** Anything consuming this repository should pin a
  released tag or commit, so that a merge does not silently change what the
  next build produces.
- **Deploying a newly built tag is a separate step** — updating the image
  reference in the relevant environment's configuration and applying it.
  Neither this repository nor the build does that.

For a testing environment, the configuration that actually matters:

| Setting | Why it matters in a deployed environment |
| --- | --- |
| `CREDENTIAL_ISSUER` | Must be the real public HTTPS URL of *this* service. Wallets resolve `.well-known` discovery and check the proof audience against it, so `localhost` or an internal hostname will not work. |
| `COORDINATOR_TOKEN` | Must be set, and must match the coordinator's `OID4VCI_ISSUER_TOKEN`. Without it, anyone who can reach the offer endpoint can have arbitrary content signed by your key. |
| `SIGNING_SERVICE_INSTANCE` | Must name an instance the signing-service actually has a seed for, or issuance fails at the last step of the flow. |
| `CREDENTIAL_CONFIGURATIONS_SUPPORTED` | Must declare `proof_types_supported`. It is now also what constrains which proof signing algorithms are accepted, so metadata and enforcement cannot drift apart. |

Note that offers, tokens and nonces are held in memory (see
[Design notes](#design-notes)), so a deployed instance should run as a single
replica until that is swapped for a shared store.

## Design notes

- **Bearer credential, no holder binding**: the proof JWT's signature/nonce/
  audience are verified (required by spec), but its key is not used to bind
  `credentialSubject.id`. A future opt-in binding step would use the
  `header.jwk` already available from `src/proof.js`'s `verifyProof`.
- **Proof algorithms come from the metadata**: `/credential` accepts only the
  algorithms the matching credential configuration advertises in
  `proof_signing_alg_values_supported`, falling back to a fixed asymmetric-only
  allowlist. Symmetric algorithms are refused outright — a proof of possession
  checked against a key the presenter chose and published in the JWT's own
  header proves nothing.
- **Nonce Endpoint is unauthenticated by design** (Section 7: "not a
  protected resource"), and therefore decoupled from any specific access
  token — `src/nonce.js` stores issued nonces independently of `/token`'s
  bookkeeping, and `/credential` just checks that the proof's `nonce` claim
  is a real, unused value, not that it was issued to *this* access token.
- **In-memory store**: offers/tokens/nonces live in an in-memory `Map` with
  TTL (`src/store.js`), fine for a single process; swap in a Redis-backed
  implementation of the same `{ get, set, delete }` shape if this needs to
  run multi-process.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports go through the
process in [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE) © FindyFi
