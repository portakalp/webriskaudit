/**
 * Reduces user input to a bare hostname so pasted URLs work:
 * "  https://www.Example.com:443/path?q=1 " -> "example.com"
 */
export const normalizeDomain = (input: string): string => {
  return input
    .trim()
    .toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, "") // scheme
    .replace(/[/?#].*$/, "") // path, query, fragment
    .replace(/:\d*$/, "") // port
    .replace(/\.$/, "") // trailing dot of a fully qualified name
    .replace(/^www\./, "")
}

/**
 * Validates a normalized hostname: dot-separated labels of letters,
 * digits and inner hyphens, ending in an alphabetic TLD.
 */
export const isValidDomain = (domain: string): boolean => {
  const domainRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$/

  return domainRegex.test(domain) && domain.length <= 253
}
