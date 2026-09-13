/**
 * Host classification, in one place.
 *
 * Two parts of the tool need the same answer to "is this host somewhere real?" —
 * the plaintext-endpoint rule, which must not demand TLS for `http://localhost`,
 * and secret triage, which must not report a documented
 * `postgres://user:pass@localhost:5432/db` as a committed credential. The regex
 * lived in `rules/security.ts`, so only the first of those two consulted it, and
 * a README telling a reader how to point the tool at their own database was
 * reported as a High credential leak.
 */

/**
 * Loopback, link-local, and the reserved names that exist for documentation.
 *
 * `example.com|org|net` are here because RFC 2606 reserves them for exactly this
 * purpose: a credential against one of them cannot be used against anything.
 */
export const LOOPBACK_OR_RESERVED =
  /^(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1?\]|host\.docker\.internal|169\.254(?:\.\d{1,3}){2}|(?:[\w-]+\.)*(?:local|localhost|internal|test|invalid|localdomain)|(?:[\w-]+\.)*example\.(?:com|org|net))$/i;

export function isLoopbackOrReserved(host: string): boolean {
  return LOOPBACK_OR_RESERVED.test(host.trim());
}

/**
 * The host of a URL that carries inline credentials, if it has one.
 *
 * Deliberately requires the `user:pass@` part: this exists to classify a
 * credential-bearing connection string, and a URL with no credential in it is
 * not this function's business. Bracketed IPv6 literals are kept whole so
 * `[::1]` can be recognised.
 */
export function credentialUrlHost(value: string): string | undefined {
  const m = /^[a-z][a-z0-9+.-]*:\/\/[^/@\s]*@(\[[^\]]+\]|[^/:?#\s]+)/i.exec(value.trim());
  return m?.[1];
}
