# ADR-0009: The web app trusts its server; say so

- Status: Proposed
- Date: 2026-10-22
- Specification: [threat-model.md §6](../security/threat-model.md#6-the-web-client-delivery-problem)

## Context

The web app's JavaScript is served by the server it should not have to trust. A compromised
server can serve code that captures the password, `SK` or plaintext. TLS, CSP and Subresource
Integrity don't help, because the attacker controls the page that declares them.

## Decision

- Accept this limit for the web app and state it in documentation and in the product.
- Make private-network mode the default.
- Keep the vault UI a static client bundle with a strict CSP.
- Treat the browser extension, and later mobile, as the clients that don't depend on the server
  for their code.
- Consider an extension-hosted vault UI in Phase 5.
- Never show a "verified" or "secure" badge for web code.

## Consequences

- Users who need protection from a compromised server must use the extension or mobile apps.
  This is risk R-01.
- Public-mode deployment increases exposure. The owner may require the extension-hosted UI first
  (D-07).

## Alternatives considered

- **Signed web bundles or a code-verification extension.** Not standardized for this use. It
  could be revisited as a feature of the Ruvee extension.
- **Dropping the web app.** It conflicts with the web-first delivery order.
