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
