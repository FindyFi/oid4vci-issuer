# oid4vci-issuer

A minimal [OID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
(OpenID for Verifiable Credential Issuance, final spec, 16 September 2025)
issuer service, implementing the pre-authorized-code flow only. It is
deliberately content-agnostic: a coordinator (your own backend, or
`digitalcredentials/issuer-coordinator` / `workflow-coordinator`) hands it an
already-built, unsigned Verifiable Credential; this service runs the
offer/token/nonce/proof protocol dance with a wallet, then signs it. How it
signs depends on the credential configuration's `format`:

| `format` | Signed by | Credential returned to the wallet |
|----------|-----------|-----------------------------------|
| `dc+sd-jwt` | this service, with its own ES256 key (`SD_JWT_SIGNING_KEY`) | an IETF SD-JWT VC: the coordinator's flat claims (with `vct`) plus `iss`, `iat` and `cnf`, no disclosures: `<jws>~` |
| `vc+sd-jwt` | this service, with its own ES256 key (`SD_JWT_SIGNING_KEY`) | a W3C VCDM 2.0 credential secured as an SD-JWT with no disclosures: `<jws>~` |
| `ldp_vc` | a [`digitalcredentials/signing-service`](https://github.com/digitalcredentials/signing-service) instance | the JSON-LD credential with a Data Integrity `proof` |

Any other format stops the service at startup. Apart from checking the
SD-JWT issuer and `vct` (see below), it never inspects or changes credential content.

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

See `.env.example`.

| Variable | Needed | Meaning |
|----------|--------|---------|
| `CREDENTIAL_ISSUER` | always | This service's own public HTTPS base URL. |
| `CREDENTIAL_CONFIGURATIONS_SUPPORTED` | always | JSON map of configuration id → OID4VCI configuration. Each entry should declare `proof_types_supported`, since that's what makes 1.0 require a proof, and therefore the Nonce Endpoint, for that credential type. |
| `SD_JWT_SIGNING_KEY` | if a configuration has format `dc+sd-jwt` or `vc+sd-jwt` | `kms:<key ARN>` (an AWS KMS key, ECC_NIST_P256 / SIGN_VERIFY; use this in production), a private EC P-256 JWK as JSON, or `generate` (dev only: a fresh key on every start, so earlier credentials stop verifying). The `kid` is always the key's RFC 7638 thumbprint. |
| `SD_JWT_PREVIOUS_KEYS` | no | After a key rotation: a JSON array of the earlier keys' **public** JWKs. They stay in `/.well-known/jwt-vc-issuer` after the current key, so credentials they signed keep verifying. See "Production keys" below. |
| `SD_JWT_X5C` | no | An X.509 chain for the SD-JWT signing key, as PEM (leaf first), or `generate` (dev only: a self-signed certificate made on every start). When set, SD-JWT headers also carry `x5c`, for wallets that find the issuer key only from a certificate (Credo-based ones such as Paradym). The leaf must hold the signing key and name the issuer in its subjectAltName (URI = the issuer URL, or DNS = its host). `iss` stays the HTTPS URL, and `/.well-known/jwt-vc-issuer` is still served. `scripts/self-signed-x5c.js` makes a stored one. |
| `SD_JWT_ISSUER` | no | The SD-JWT `iss`. Defaults to `CREDENTIAL_ISSUER`. Must be an origin with no path or trailing slash. |
| `SIGNING_SERVICE_URL`, `SIGNING_SERVICE_INSTANCE`, `SIGNING_SERVICE_SUITE` | if a configuration has format `ldp_vc` | Where to forward `ldp_vc` signing. |
| `COORDINATOR_TOKEN` | beyond local dev | Shared secret for offer creation. |
| `PORT` | no | Defaults to 4007. |
| `LOG_REQUESTS` | no | `1` logs one line per request: the body's shape (no values, only proof JWT headers), the error returned, and the user agent. For wallet interop debugging. |

The service refuses to start if a configuration's format is unsupported, or
if what that format needs isn't configured.

To make a local key for `SD_JWT_SIGNING_KEY` (outside production):

```sh
node -e "import('jose').then(async j => console.log(JSON.stringify(await j.exportJWK((await j.generateKeyPair('ES256', { extractable: true })).privateKey))))"
```

### Production keys

In production the signing key is an AWS KMS key, so the private key never
leaves KMS. Create it with key spec `ECC_NIST_P256` and usage `SIGN_VERIFY`,
and set `SD_JWT_SIGNING_KEY=kms:<key ARN>`. The task's IAM role needs
`kms:GetPublicKey` (at startup) and `kms:Sign` (once per credential) on it.
The service hashes locally and sends KMS only the SHA-256 digest, so large
credentials don't hit the 4 KB limit on KMS messages.

Make the `x5c` certificate once and store it, instead of using `generate`:

```sh
SD_JWT_SIGNING_KEY=kms:<key ARN> CREDENTIAL_ISSUER=https://issuer.example \
  node scripts/self-signed-x5c.js [days] > x5c.pem
```

This needs AWS credentials allowed to call `kms:GetPublicKey` and `kms:Sign`
on the key. The certificate is self-signed, valid for 3650 days by default,
and names the issuer as SAN URI and SAN DNS. Credo-based wallets (Paradym)
ask the user to accept an unknown issuer; a stable certificate means the same
issuer each time. When it expires, those wallets stop accepting credentials
that carry it, so renew it well before then: run the script again and
redeploy (the key and `kid` stay the same).

**Rotating the key.** KMS doesn't rotate asymmetric keys itself, so a
rotation is a new key:

1. Create the new KMS key, and make a certificate for it with the script.
   Allow the task's role to use both keys, so the running service can still
   sign while the new one starts.
2. Add the **current** key's public JWK (from `/.well-known/jwt-vc-issuer`)
   to `SD_JWT_PREVIOUS_KEYS`.
3. Point `SD_JWT_SIGNING_KEY` at the new key, set `SD_JWT_X5C` to the new
   certificate, and redeploy. The service refuses to start if the certificate
   doesn't hold the new key.
4. Keep the old key's JWK in `SD_JWT_PREVIOUS_KEYS` for as long as
   credentials it signed should verify. Credentials carry no `exp`, so in
   practice that's for good. You can disable the old KMS key (it's no longer
   used to sign); don't schedule its deletion until you're sure.

Credentials already in wallets keep their own `x5c` header, so the old
certificate goes on working for them until it expires.

An SD-JWT VC configuration looks like this. `vct` must be set; if it is a
URL under `CREDENTIAL_ISSUER`, this service serves SD-JWT VC Type Metadata
there, built from `credential_metadata.display`:

```json
"OpenBadgeCredentialSdJwtVc": {
  "format": "dc+sd-jwt",
  "vct": "https://issuer.example/vct/OpenBadgeCredential",
  "cryptographic_binding_methods_supported": ["jwk"],
  "credential_signing_alg_values_supported": ["ES256"],
  "proof_types_supported": { "jwt": { "proof_signing_alg_values_supported": ["ES256"] } },
  "credential_metadata": { "display": [{ "name": "Open Badge", "locale": "en" }] }
}
```

At startup, this service fetches each `dc+sd-jwt` configuration's `vct` and
computes its `vct#integrity` (`sha256-<base64>` of the exact bytes, SRI); the
issued credentials carry it. To pin it (production), add `"vct#integrity"` to
the configuration: if the fetched hash differs, the service refuses to start,
and if the fetch fails it starts with the pinned value and logs a warning.
Unpinned (dev), a failed fetch means credentials are issued without
`vct#integrity`, with a warning. Coordinators must not send `vct#integrity`.

A VCDM 2.0 SD-JWT configuration looks like this:

```json
"OpenBadgeCredentialSdJwt": {
  "format": "vc+sd-jwt",
  "credential_definition": {
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"],
    "type": ["VerifiableCredential", "OpenBadgeCredential"]
  },
  "credential_signing_alg_values_supported": ["ES256"],
  "proof_types_supported": { "jwt": { "proof_signing_alg_values_supported": ["ES256"] } }
}
```

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

`test/issuance.test.js` starts the app in-process on a random port with a
stubbed signing-service and a generated SD-JWT key, and walks through the
whole flow with a fake wallet. It verifies issued SD-JWTs against the
published JWKS. `test/startup.test.js` covers configuration errors and key loading.

## Endpoints

Coordinator-facing (should sit behind network isolation and/or `COORDINATOR_TOKEN`):

- `POST /instance/:tenant/offers` — body `{ credentialConfigurationId, unsignedCredential, txCode? }`.
  Returns `{ preAuthorizedCode, txCode, offerUri, expiresIn }`. `offerUri` is
  an `openid-credential-offer://` link, ready to render as a QR code or deep
  link. Returns 400 if `credentialConfigurationId` isn't configured. For a
  `vc+sd-jwt` configuration it also returns 400 if the credential's issuer
  (`issuer`, or `issuer.id`) isn't exactly the SD-JWT issuer URL, or if
  `validFrom` isn't a date-time. For a `dc+sd-jwt` configuration it returns
  400 if `vct` isn't the configuration's, or if the claims contain any of
  `iss`, `iat`, `nbf`, `exp`, `cnf`, `_sd`, `_sd_alg` or `vct#integrity`. Nothing is
  overwritten silently.

Wallet-facing (public):

- `GET /.well-known/openid-credential-issuer` — issuer metadata, including
  `nonce_endpoint`.
- `GET /.well-known/oauth-authorization-server` — OAuth 2.0 Authorization
  Server Metadata (RFC 8414). This service is its own authorization server, so
  1.0 wallets find `token_endpoint` here. It advertises only the
  pre-authorized code grant, with anonymous access.
- `GET /.well-known/openid-configuration` — the same RFC 8414 document, for
  wallets that fall back to this path. It is not an OpenID Federation Entity
  Configuration.
- `GET /.well-known/jwt-vc-issuer` — only when SD-JWT signing is configured.
  JWT VC Issuer Metadata: `{ "issuer": <issuer URL>, "jwks": { "keys": [<public JWK with kid, alg, use: "sig">] } }`.
  Verifiers use it to find the key for an SD-JWT's `iss` and `kid`.
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
  `nonce` claim is a real, unused value from `/nonce`, signs the credential
  (see the table above), and returns
  `200 { "credentials": [{ "credential": <signed VC or SD-JWT string> }] }`
  (Section 8.3; the old top-level `credential` is gone in 1.0 final). There is
  always exactly one element, and the response is `Cache-Control: no-store`.

Operational:

- `GET /healthz` — what the container `HEALTHCHECK` and compose's
  `service_healthy` condition wait on.

## The `vc+sd-jwt` credential

- JOSE header: `{ "typ": "vc+sd-jwt", "kid": <JWK thumbprint>, "alg": "ES256" }`.
- Payload: the unsigned VC exactly as the coordinator sent it, plus `iss` (the
  SD-JWT issuer URL), `iat` (issuance time) and `nbf` (from `validFrom`, if present).
- No disclosures, so no `_sd` or `_sd_alg`, and the compact form ends in a
  single `~`. No `cnf`: the credential is not bound to the wallet's key.
- All format-specific code is in `src/sdjwt.js`.

Note that OID4VCI 1.0 final has no format identifier for "VCDM 2.0 secured
with SD-JWT". In the OID4VCI drafts, `vc+sd-jwt` meant IETF SD-JWT VC, which
1.0 renamed `dc+sd-jwt`, so some wallets may expect a `vct` claim here.

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

- **Holder binding is per configuration**: the proof JWT's signature, nonce
  and audience are always verified. An SD-JWT configuration that lists `jwk`
  in `cryptographic_binding_methods_supported` gets the proof's public key as
  `cnf.jwk`; without it the credential is a bearer credential. Some wallets
  (Procivis One) refuse unbound credentials, and some (Heidi) send no proof
  unless binding is advertised.
- **Pre-1.0 proofs**: a singular `proof: { proof_type: "jwt", jwt }` is
  accepted as well as the 1.0 `proofs.jwt` array.
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
