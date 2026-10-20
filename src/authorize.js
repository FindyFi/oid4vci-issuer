// The authorization endpoint (RFC 6749 section 3.1), advertised in the
// authorization server metadata for wallets that require one (Toppan). This
// service implements only the pre-authorized code flow, so every request is
// refused with `unsupported_response_type`.
//
// The error is never sent by redirect, even to a well-formed `redirect_uri`:
// there is no client registry, so no client_id or redirect_uri is ever
// valid, and RFC 6749 section 4.1.2.1 says the server MUST NOT then redirect.
// Redirecting to whatever URI the request names would make this an open
// redirector (RFC 6749 section 10.15).
export function authorizeHandler(req, res) {
  res.status(400).json({
    error: 'unsupported_response_type',
    error_description: 'This issuer supports only the pre-authorized code flow. Scan a credential offer instead.',
  })
}
