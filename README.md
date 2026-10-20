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
| `dc+sd-jwt` | this service, with its own ES256 key (`SD_JWT_SIGNING_KEY`) | an IETF SD-JWT VC: the coordinator's flat claims (with `vct`) plus `iss`, `iat` and `cnf`. The claims the offer lists in `disclosable` are selectively disclosable (`<jws>~<disclosure>~…~`); with none, `<jws>~` |
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

See `.env.example`. It is also the machine-readable list of every variable
the service reads: the comment line directly above each variable is a tag,
`# @env required` or `# @env optional`, optionally followed by ` secret`
(take the value from a secret store, not plain task environment). With
`NODE_ENV=production` (the Docker image sets it) the service refuses to start
and names every missing required variable. A test keeps the list in step with
the code, and deployment config should follow it. `SIGNING_SERVICE_*` are
optional only because they matter just for `ldp_vc`; set all three wherever
`ldp_vc` is offered.

| Variable | Needed | Meaning |
|----------|--------|---------|
| `CREDENTIAL_ISSUER` | always | This service's own public HTTPS base URL. |
| `CREDENTIAL_CONFIGURATIONS_SUPPORTED` | always | JSON map of configuration id → OID4VCI configuration. Each entry should declare `proof_types_supported`, since that's what makes 1.0 require a proof, and therefore the Nonce Endpoint, for that credential type. |
| `SD_JWT_SIGNING_KEY` | if a configuration has format `dc+sd-jwt` or `vc+sd-jwt` | `kms:<key ARN>` (an AWS KMS key, ECC_NIST_P256 / SIGN_VERIFY; use this in production), a private EC P-256 JWK as JSON, or `generate` (dev only: a fresh key on every start, so earlier credentials stop verifying). The `kid` is always the key's RFC 7638 thumbprint. |
| `SD_JWT_PREVIOUS_KEYS` | no | After a key rotation: a JSON array of the earlier keys' **public** JWKs. They stay in `/.well-known/jwt-vc-issuer` after the current key, so credentials they signed keep verifying. See "Production keys" below. |
| `SD_JWT_X5C` | no | An X.509 chain for the SD-JWT signing key, as PEM (leaf first), or `generate` (dev only: a self-signed certificate made on every start). When set, SD-JWT headers also carry `x5c`, for wallets that find the issuer key only from a certificate (Credo-based ones such as Paradym). The leaf must hold the signing key and name the issuer in its subjectAltName (URI = the issuer URL, or DNS = its host). `iss` stays the HTTPS URL, and `/.well-known/jwt-vc-issuer` is still served. `scripts/self-signed-x5c.js` makes a stored one. |
| `SD_JWT_ISSUER` | no | The SD-JWT `iss`. Defaults to `CREDENTIAL_ISSUER`. Must be an origin with no path or trailing slash. |
| `OID4VCI_ISSUER_METADATA` | no | The issuer `display` (name and logo per language) for the issuer metadata, as `{"display":[…]}` (see "Issuer display" below). Make it with `npm run metadata:setup`. |
| `FEDERATION_ENTITY_METADATA` | no | Turns on the OpenID Federation Entity Configuration (see "OpenID Federation" below): a JSON object whose `display_name` is required unless `OID4VCI_ISSUER_METADATA` has a display to take it from. Make it with `npm run federation:setup`. Needs `SD_JWT_SIGNING_KEY`, and `SD_JWT_ISSUER` (if set) must equal `CREDENTIAL_ISSUER`. |
| `FEDERATION_AUTHORITY_HINTS` | no | JSON array of https entity IDs of the trust anchor or intermediates above this issuer. |
| `FEDERATION_TRUST_MARKS` | no | JSON array of trust marks, published as-is. |
| `FEDERATION_ENTITY_CONFIGURATION_TTL` | no | Seconds the Entity Configuration is valid. Default 86400. |
| `SIGNING_SERVICE_URL`, `SIGNING_SERVICE_INSTANCE`, `SIGNING_SERVICE_SUITE` | if a configuration has format `ldp_vc` | Where to forward `ldp_vc` signing. |
| `COORDINATOR_TOKEN` | production (required, secret) | Shared secret for offer creation. |
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

An SD-JWT VC configuration looks like this. `vct` must be set. This service
does not host the Type Metadata; `vct` points at a document hosted elsewhere
(see below for `vct#integrity`):

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

## Issuer display

`OID4VCI_ISSUER_METADATA` puts a `display` into
`/.well-known/openid-credential-issuer` (OID4VCI 1.0 Section 12.2.4), so wallets
can show who issues: one entry per language, each with a `name` and optionally a
`logo` (`uri`, https or a `data:` URI, and `alt_text`). Without it the metadata
has no `display`, as before. The service refuses to start on an invalid one: an
empty array, two entries for one language, a missing name, a logo URI that isn't
https or `data:`, or a member it doesn't know.

List the main language first: several wallets show only the first entry (see
"Display data that wallets actually use" in the design notes). Use an https URL
to a PNG under 200 KB for the logo: some wallets render no SVG, don't read
`data:` URIs, or drop large logos.

The script asks for the languages first, then the name in each, the logo, and
the logo's description in each:

```sh
npm run metadata:setup                       # asks, then adds the line to ./.env
npm run metadata:setup -- --lang=fi,en,sv    # these languages, in this order
node scripts/issuer-metadata.js              # same questions, only prints the line
node scripts/issuer-metadata.js --lang=fi,en --name "fi=Esimerkkiyliopisto" \
  --name "en=Example University" --logo-uri https://example.org/logo.png \
  --logo-alt "fi=Esimerkkiyliopiston logo" --logo-alt "en=Example University logo"
```

With `--name` it asks nothing; the languages are then `--lang`, or the ones the
`--name` options give. `--write [file]` and `--json` work as in
`federation:setup` (below).

The same name and logo also serve OpenID Federation: when
`FEDERATION_ENTITY_METADATA` has no `display_name`, the Entity Configuration
gets the English name (or the first) as `display_name`, and every language's
name as `display_name#<language>` (OpenID Federation 1.0 Section 14). When it has
no `logo_uri`, it gets the display's logo, if that is an https URL. What
`FEDERATION_ENTITY_METADATA` sets itself is kept. Federation stays off until
`FEDERATION_ENTITY_METADATA` is set; `{}` turns it on with only the name and logo
from the display.

## OpenID Federation

Set `FEDERATION_ENTITY_METADATA` and the service publishes an OpenID
Federation 1.0 Entity Configuration at `/.well-known/openid-federation`. It
is one document that serves both
[DIIP v5](https://fidescommunity.github.io/DIIP/#credential-issuance) and the
OpenID Federation Wallet Architectures profile ("Credential Verifiers
Establishing Trust in Credential Issuers"): a compact JWS (`typ`
`entity-statement+jwt`, content type `application/entity-statement+jwt`) with

- `iss` = `sub` = `CREDENTIAL_ISSUER`, the Entity Identifier, plus `iat`,
  `exp` and a root `jwks` (a JWK Set) with the key that signs it;
- `metadata.federation_entity`: your `FEDERATION_ENTITY_METADATA`, with the
  name and logo from the issuer display where it has none (see "Issuer display");
- `metadata.openid_credential_issuer`: the issuer metadata, plus `jwks` with the
  credential-signing keys;
- `metadata.vc_issuer.jwks`: the same keys, where DIIP looks for them (their
  `kid` is the SD-JWT header's `kid`);
- `metadata.oauth_authorization_server`: the RFC 8414 metadata;
- `authority_hints` and `trust_marks`, when configured.

Credentials in the `dc+sd-jwt` format also get a `fed` claim with the Entity
Identifier (coordinators must not send it). `vc+sd-jwt` credentials get a
`termsOfUse` entry `{ "type": "OpenIDFederation", "policyId": <Entity Identifier> }`,
added after any `termsOfUse` the coordinator sent.

The Entity Configuration is signed with `SD_JWT_SIGNING_KEY`, so the root
`jwks` and the credential keys are the same. The code takes the federation
key as a separate input (`federation.key` in `index.js`), so giving it its own
`FEDERATION_SIGNING_KEY` later is a small change. You would want that if a
trust anchor pins your federation key and you rotate the credential key.

The service refuses to start if federation is on but there's no
`SD_JWT_SIGNING_KEY`, if `SD_JWT_ISSUER` differs from `CREDENTIAL_ISSUER`, or if
any `FEDERATION_*` value is invalid (no `display_name` and no issuer display, a hint that isn't an
https URL, ...).

### Making the `FEDERATION_*` values

You don't have to write the JSON yourself. The script asks for the values
and prints (or writes) ready-to-use lines:

```sh
npm run federation:setup        # asks questions, then adds the lines to ./.env
node scripts/federation-metadata.js     # same questions, only prints the lines
```

```
Display name, e.g. "Example University": Example University
Organization name, e.g. the legal name (optional, Enter to skip): Example University Oy
Contacts (e-mail addresses or URLs), comma separated (optional, Enter to skip): it@example.org
...
FEDERATION_ENTITY_METADATA='{"display_name":"Example University","organization_name":"Example University Oy","contacts":["it@example.org"]}'
```

If `OID4VCI_ISSUER_METADATA` already has a display (in the environment or in
the env file), the display name and logo may be left empty: the service takes
them from it. Run `npm run metadata:setup` first, then.

Options (any of the value options skips the questions):

| Option | |
|--------|---|
| `--write [file]` | Put the lines in an env file (default `.env`): an existing `FEDERATION_*` line, or a commented-out one, is replaced in place, and the rest are appended. The file is created if needed. |
| `--json` | Print only the metadata JSON, for a secret store or a Terraform variable. |
| `--display-name`, `--organization-name`, `--homepage-uri`, `--logo-uri`, `--policy-uri` | The values. Every URL must be https. |
| `--contact`, `--authority-hint` | May be repeated. |

The `NAME='<json>'` form reads the same in `.env` (dotenv), Docker Compose
and a POSIX shell. A single quote inside a value is written as the JSON
escape `\u0027`, so it can't break the quoting. `FEDERATION_TRUST_MARKS` isn't
asked for, because trust marks come from the party that issues them: paste
the JSON array they gave you into the variable.

For the Docker Compose stack, `docker compose` reads `.env` next to
`docker-compose.yml` and passes the `FEDERATION_*` values on to the service,
so run the script there and restart. Check the result with

```sh
curl -s http://localhost:4007/.well-known/openid-federation | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

Whether a trust anchor will accept the entity is up to its registration
process, which this service doesn't take part in.

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

- `POST /instance/:tenant/offers` — body `{ credentialConfigurationId, unsignedCredential, txCode?, disclosable? }`.
  Returns `{ preAuthorizedCode, txCode, offerUri, expiresIn }`. `offerUri` is
  an `openid-credential-offer://` link, ready to render as a QR code or deep
  link. Returns 400 if `credentialConfigurationId` isn't configured. For a
  `vc+sd-jwt` configuration it also returns 400 if the credential's issuer
  (`issuer`, or `issuer.id`) isn't exactly the SD-JWT issuer URL, or if
  `validFrom` isn't a date-time. For a `dc+sd-jwt` configuration it returns
  400 if `vct` isn't the configuration's, or if the claims contain any of
  `iss`, `iat`, `nbf`, `exp`, `cnf`, `_sd`, `_sd_alg`, `vct#integrity` or `fed`. Nothing is
  overwritten silently.
  `disclosable` (`dc+sd-jwt` only) is an array of top-level claim names to
  make selectively disclosable, such as `["sub", "identifier"]`: they leave
  the payload for `_sd` digests (`_sd_alg: "sha-256"`) and travel as
  disclosures, so the holder decides whether to present them. The offer is
  rejected with 400 if the list names a claim that isn't in the credential,
  repeats one, names `vct` or `status` (SD-JWT VC keeps those always
  disclosed), or is sent for any other format.

Wallet-facing (public):

- `GET /.well-known/openid-credential-issuer` — issuer metadata, including
  `nonce_endpoint`.
- `GET /.well-known/oauth-authorization-server` — OAuth 2.0 Authorization
  Server Metadata (RFC 8414). This service is its own authorization server, so
  1.0 wallets find `token_endpoint` here. It advertises only the
  pre-authorized code grant, with anonymous access, and
  `response_types_supported: []`. It also names `authorization_endpoint`,
  for wallets that require one (see "Interoperability").
- `GET /.well-known/openid-configuration` — the same RFC 8414 document, for
  wallets that fall back to this path. It is not an OpenID Federation Entity
  Configuration (that is `/.well-known/openid-federation`).
- `GET /.well-known/openid-federation` — only when `FEDERATION_ENTITY_METADATA`
  is set. The OpenID Federation Entity Configuration, a signed JWT. See "OpenID
  Federation" above.
- `GET /.well-known/jwt-vc-issuer` — only when SD-JWT signing is configured.
  JWT VC Issuer Metadata: `{ "issuer": <issuer URL>, "jwks": { "keys": [<public JWK with kid, alg, use: "sig">] } }`.
  Verifiers use it to find the key for an SD-JWT's `iss` and `kid`.
- `GET /.well-known/did.json` — only when SD-JWT signing is configured. A
  `did:web` DID Document for `CREDENTIAL_ISSUER`'s host (`did:web:<host>`)
  whose verification methods (`JsonWebKey2020`, in `assertionMethod` and
  `authentication`) are the keys in the JWKS above, each with the key's `kid`
  as its fragment. Credentials still name the plain HTTPS URL as `iss`; this
  is for wallets that identify every issuer by a DID (see "Interoperability").
- `GET /instance/:tenant/offers/:code` — the hosted `credential_offer` JSON.
- `GET /instance/:tenant/offers/:code/status` — `{ used: boolean }`, for a
  coordinator that wants to poll for pickup.
- `GET /authorize` — always 400 `{ "error": "unsupported_response_type" }`:
  there is no authorization code flow. It never redirects, not even to a
  `redirect_uri` in the request, since no client is registered (RFC 6749
  section 4.1.2.1). Wallets on the pre-authorized code flow never call it.
- `POST /token` — pre-authorized_code grant (form-encoded, standard OAuth2
  token endpoint shape). Per 1.0 (unlike some pre-1.0 drafts), the response
  does **not** include `c_nonce` — get that from `/nonce` instead.
- `POST /nonce` — Section 7. Unauthenticated (not a protected resource, per
  spec), empty request body, returns `{ c_nonce }`.
- `POST /credential` — body must include a matching `credential_configuration_id`
  and a `proofs` object (plural, per Section 8.2 — `{"proofs":{"jwt":["<jwt>"]}}`,
  not a singular `proof`). This service only supports exactly one proof per
  request (one offer = one credential instance, no batch issuance). Verifies
  the proof JWT (signature against the key in its `jwk` header or `did:jwk`
  `kid`, `aud`, `typ: openid4vci-proof+jwt`, and that its
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
  single `~`. `cnf` is added only when the configuration lists `jwk` in
  `cryptographic_binding_methods_supported`.
- All format-specific code is in `src/sdjwt.js`.

Note that OID4VCI 1.0 final has no format identifier for "VCDM 2.0 secured
with SD-JWT". In the OID4VCI drafts, `vc+sd-jwt` meant IETF SD-JWT VC, which
1.0 renamed `dc+sd-jwt`, so some wallets expect a `vct` claim here. In
interop testing (Heidi, Procivis One, Talao, Paradym) no wallet accepted
`vc+sd-jwt`, while `dc+sd-jwt` worked in Heidi, Procivis One and Talao. Prefer
`dc+sd-jwt`; `vc+sd-jwt` stays for wallets that implement the VCDM 2.0 profile.

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

## Interoperability

Wallets differ in how closely they follow the specs, and a credential that never reaches the wallet
helps nobody. Two principles guide what this service accepts:

- **Robustness principle: be liberal in what we accept, strict in what we send.** Where a wallet's
  request is unambiguous but not exactly per spec, accept it. Everything this service emits
  (metadata, tokens, credentials) stays exactly per spec.
- **Accommodate [DIIP](https://fidescommunity.github.io/DIIP/)-compliant wallets as far as we can**,
  also beyond our own choices. For example, `/.well-known/did.json` is published for wallets that
  identify issuers by DIDs, although credentials name a plain HTTPS URL as `iss`.

Each tolerance names the wallet that needed it, and has a test named after that wallet
(`test/issuance.test.js`):

| Accepted | Spec says | Needed by |
| --- | --- | --- |
| The holder key as a `did:jwk` DID URL in the proof's `kid`, instead of a `jwk` header. The credential gets `cnf.jwk` and `cnf.kid` (the DID URL). Other DID methods are refused, since resolving them would mean fetching URLs a wallet chose. | OID4VCI 1.0 App. F.1 allows `kid`, `jwk` or `x5c`; DIIP v5 requires `did:jwk`, and `cnf.kid` from the holder's DID document | UniMe |
| A proof `aud` with one trailing slash more or less than the Credential Issuer Identifier. | App. F.1: `aud` MUST be the Credential Issuer Identifier | UniMe |
| The access token with any case of the `Bearer` scheme, such as the `bearer` that `/token` returns as `token_type`. | RFC 7235 section 2.1: the scheme is case-insensitive | (found with a scripted wallet) |
| A `did:web` document at `/.well-known/did.json`. | UniMe requires one for every OID4VCI issuer (its ADR 0001); DIIP v5 asks for `did:web` support | UniMe |
| An `authorization_endpoint` in the authorization server metadata, although only the pre-authorized code grant is offered. `/authorize` answers `unsupported_response_type`. | RFC 8414: `authorization_endpoint` is REQUIRED unless no grant uses it | Toppan |
| A pre-1.0 singular `proof: { proof_type: "jwt", jwt }` next to the 1.0 `proofs.jwt` array. | OID4VCI 1.0 section 8.2: `proofs` | pre-1.0 (draft 13) wallets |
| A proof with both `jwk` and `kid`: `jwk` wins, and `kid` is taken as a plain key id. | App. F.1: `kid` MUST NOT be present with `jwk` | (by the principle) |

## Design notes

- **Holder binding is per configuration**: the proof JWT's signature, nonce
  and audience are always verified. An SD-JWT configuration that lists `jwk`
  in `cryptographic_binding_methods_supported` gets the proof's public key as
  `cnf.jwk` (plus `cnf.kid` when the wallet named the key by a DID URL); without it the credential is a bearer credential. Some wallets
  (Procivis One) refuse unbound credentials, and some (Heidi) send no proof
  unless binding is advertised.
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
- **Issuer metadata members we leave out on purpose** (reviewed 2026-10-20
  against OID4VCI 1.0 section 12.2.4 and the source of Procivis One, Paradym
  (Credo), Heidi (Kapun SDK), UniMe and Altme/Talao):
  - `authorization_servers`: this service is its own authorization server, and
    every wallet checked falls back to the issuer (`/.well-known/oauth-authorization-server`).
  - `deferred_credential_endpoint`: issuance is always immediate.
  - `credential_request_encryption`, `credential_response_encryption`: TLS
    protects the exchange. Advertising them is not harmless: Procivis One then
    encrypts, even with `encryption_required: false`, and fails on a plain
    response.
  - `batch_credential_issuance`: one credential per offer. Procivis would ask
    for exactly `batch_size` credentials, Paradym for up to 10; the credentials
    name their holder, so batches would add little unlinkability.
  - Signed metadata (section 12.2.3): Procivis and Paradym fall back to the
    JSON; Altme shows the certificate's name and no logo when it is present.
    The Entity Configuration is the signed form, for those who need one.
  - `key_attestations_required`: not required (the spec says it MUST NOT be
    present then; Paradym fails on it).
  - `notification_endpoint`: not yet; planned (Procivis One sends
    notifications, the others checked don't).
- **Display data that wallets actually use**: the first `display` entry is
  what most wallets show (UniMe and Heidi's credential card take only the
  first; Paradym matches only `en-*`, then an entry without a locale, then the
  first), so list the main language first. Logos: an https URL to a small PNG
  (UniMe downloads only PNG, JPEG or SVG up to 2 MB and doesn't read `data:`
  URIs; Procivis drops logos over 200 KB; Altme recognises SVG only by a
  `.svg` suffix). Per-configuration `credential_metadata.display` colours are
  shown by Procivis, Altme and Heidi (`background_color`); Paradym prefers the
  SD-JWT VC type metadata's display for `dc+sd-jwt`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports go through the
process in [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE) © FindyFi
