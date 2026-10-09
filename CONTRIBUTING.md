# Contributing

## Getting set up

```sh
git clone https://github.com/FindyFi/oid4vci-issuer.git
cd oid4vci-issuer
npm install
npm test
```

Node 20 or newer is required (`.nvmrc` pins the version used for development). CI runs the suite on
Node 20, 22 and 24, so please keep the code working across that range.

The test suite needs nothing running beforehand — no Docker, no network, no signing-service. It boots
`index.js` in a child process against a stub signing-service and drives the full flow.

To exercise the real thing instead, `docker compose up --build` brings up this service together with
a `signing-service` instance.

## Making a change

- Add or update tests alongside behaviour changes. The suite drives the published entrypoint over
  HTTP rather than importing handlers, so a change to the env-var wiring is covered too.
- Keep this service content-agnostic. It never inspects, builds or validates credential content —
  that belongs in the coordinator (see the README). A change that needs to know what a credential
  *means* is a sign the logic belongs elsewhere.
- Match the surrounding style: two-space indentation, single quotes, no semicolons.
- Update `CHANGELOG.md` under `## [Unreleased]`.

## Spec changes

Most of the judgement here is about what
[OID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) requires —
and several details changed between the pre-1.0 drafts and the final spec (`c_nonce` leaving the
token response, the separate Nonce Endpoint, `proofs` becoming plural). When a change touches
protocol behaviour, please cite the section it follows, so the reasoning survives in review.

## Keeping the image buildable

The image that gets deployed is built from this repository's `Dockerfile`, outside this repository.
`package-lock.json` is committed and `npm ci` depends on it, so a change that touches dependencies
must commit the updated lockfile. CI builds the image on every pull request to catch this.

## Releasing

Bump `version` in `package.json`, move the `CHANGELOG.md` entries out of `## [Unreleased]`, and tag
the commit, so deployments have something readable to pin.
