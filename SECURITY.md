# Security policy

## Supported versions

The project is small and moves as a single line of development. Fixes land on `main`; there are no
maintained release branches.

## Reporting a vulnerability

Please report suspected vulnerabilities privately, through GitHub's
[private vulnerability reporting](https://github.com/FindyFi/oid4vci-issuer/security/advisories/new)
for this repository. Please do not open a public issue for a security problem.

Include what you need to describe the problem: affected version or commit, what an attacker could do,
and a way to reproduce it if you have one.

## What this service is responsible for

It runs the OID4VCI pre-authorized-code flow and then asks a
[`signing-service`](https://github.com/digitalcredentials/signing-service) instance to sign whatever
credential a coordinator gave it. It holds no signing keys of its own, and never inspects credential
content. The security-relevant surface is therefore the protocol bookkeeping: single-use offers,
single-use access tokens, single-use nonces, and proof verification.

Two properties are worth stating plainly, because they are design decisions rather than oversights:

- **Offers are bearer credentials.** The wallet's proof-of-possession JWT is verified (algorithm,
  signature, audience, `typ`, and a nonce this service issued and has not yet seen used), but the key
  in it is not bound to `credentialSubject.id`. Anyone holding a valid pre-authorized code can
  therefore collect the credential. Use `txCode` where that matters.
- **The Nonce Endpoint is unauthenticated**, as OID4VCI 1.0 Section 7 requires. It is therefore
  reachable by anyone, and nonces are held in memory until they expire.

## Deployment expectations

`POST /instance/:tenant/offers` gets arbitrary content signed by your signing-service key. It is the
one endpoint that must not be publicly reachable. Set `COORDINATOR_TOKEN`, and put it behind network
isolation as well wherever you can. The remaining endpoints are wallet-facing and meant to be public.

This service keeps offers, tokens and nonces in memory, and applies no rate limiting of its own.
Deployments are expected to sit behind an ingress that provides it.
