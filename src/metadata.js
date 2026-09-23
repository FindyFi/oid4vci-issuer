export function createMetadataHandler({ credentialIssuer, credentialConfigurationsSupported }) {
  return function metadataHandler(req, res) {
    res.json({
      credential_issuer: credentialIssuer,
      credential_endpoint: `${credentialIssuer}/credential`,
      token_endpoint: `${credentialIssuer}/token`,
      // Required whenever a credential_configurations_supported entry
      // declares proof_types_supported (OID4VCI 1.0 Section 12.2.4) - this
      // service always requires a proof, so it always advertises this.
      nonce_endpoint: `${credentialIssuer}/nonce`,
      credential_configurations_supported: credentialConfigurationsSupported,
    })
  }
}

// RFC 8414 authorization server metadata.
//
// The credential issuer metadata above carries a `token_endpoint`, which is
// enough for a client that reads it directly - but that is not how wallets
// discover the token endpoint. OID4VCI 1.0 Section 11.2.3 says that when the
// issuer metadata has no `authorization_servers`, the credential issuer *is*
// the authorization server, and its metadata is retrieved per RFC 8414 from
// `/.well-known/oauth-authorization-server`. Wallets that follow that path -
// Procivis does - get a 404 and abort the invitation before they ever reach
// `/token`, with an error that only says the metadata download failed.
//
// `/.well-known/openid-configuration` is served from the same document
// because it is the conventional fallback a wallet tries next.
export function createAuthorizationServerMetadataHandler({ credentialIssuer }) {
  return function authorizationServerMetadataHandler(req, res) {
    res.json({
      issuer: credentialIssuer,
      token_endpoint: `${credentialIssuer}/token`,
      // Pre-authorized code is the only flow this service implements: there
      // is no authorization endpoint, so no `response_types_supported` and
      // no authorization_code grant to advertise.
      grant_types_supported: ['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
      // The token endpoint takes the pre-authorized code itself as the
      // credential; it authenticates no client.
      token_endpoint_auth_methods_supported: ['none'],
      'pre-authorized_grant_anonymous_access_supported': true,
    })
  }
}
