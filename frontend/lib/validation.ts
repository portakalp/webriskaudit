/**
 * Domain input handling, kept close to the API's normalize_domain
 * (backend/src/webriskaudit/net/domain.py) so most mistakes are caught before
 * a request is sent. The API still applies its full rules (IDNA validation,
 * special-use names such as .local or .test) and explains any refusal.
 */

export type DomainCheck = { ok: true; domain: string } | { ok: false; error: string }

const MAX_INPUT_LENGTH = 2048
const MAX_NAME_LENGTH = 253
const SCHEME = /^([a-z][a-z0-9+.-]*):\/\//i
const LDH_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
// Browsers treat a host whose last label is a number (decimal or 0x-hex) as
// an IPv4 address, e.g. "127.1" or "0x7f.1".
const NUMERIC_LABEL = /^(?:[0-9]+|0x[0-9a-f]*)$/

const ENTER_DOMAIN = "Enter a domain name such as example.com."
const NO_IP_ADDRESSES = "IP addresses cannot be scanned; enter a domain name."

/**
 * Reduces user input to the hostname that gets scanned, so pasted URLs work:
 * " https://user@www.Example.com:443/path?q=1 " -> "www.example.com".
 * Drops the scheme, userinfo, port, path and a trailing dot, lower-cases the
 * name and converts an internationalized name to its ASCII (xn--) form.
 * "www." is kept: the API scans the host as given.
 */
export function normalizeDomain(input: string): string {
  const hostPort = splitInput(input.trim()).hostPort
  const host = isIpv6Like(hostPort) ? hostPort : hostPort.split(":", 1)[0]
  const name = toAscii(host)
  return name.endsWith(".") ? name.slice(0, -1) : name
}

/** Normalizes the input, then checks that the result is a domain the API will scan. */
export function validateDomain(input: string): DomainCheck {
  const text = input.trim()
  if (!text) return invalid(ENTER_DOMAIN)
  if (text.length > MAX_INPUT_LENGTH) return invalid("The input is too long to be a domain name.")

  const { scheme, hostPort } = splitInput(text)
  if (scheme && scheme !== "http" && scheme !== "https") {
    return invalid("Only http and https URLs are supported.")
  }
  if (isIpv6Like(hostPort)) return invalid(NO_IP_ADDRESSES)
  const port = hostPort.includes(":") ? hostPort.slice(hostPort.indexOf(":") + 1) : ""
  if (port && !(/^\d+$/.test(port) && Number(port) <= 65535)) {
    return invalid("The port number is not valid.")
  }

  const domain = normalizeDomain(text)
  const error = hostnameError(domain)
  return error ? invalid(error) : { ok: true, domain }
}

function hostnameError(name: string): string | null {
  if (!name) return ENTER_DOMAIN
  if (!isAscii(name)) return "The domain is not a valid internationalized name."
  const labels = name.split(".")
  if (NUMERIC_LABEL.test(labels[labels.length - 1])) return NO_IP_ADDRESSES
  if (name.length > MAX_NAME_LENGTH) return "The domain name is longer than 253 characters."
  if (labels.length < 2) return "Enter a full domain name such as example.com."
  if (!labels.every((label) => LDH_LABEL.test(label))) {
    return "Each part of a domain name must be 1-63 letters, digits or hyphens and cannot start or end with a hyphen."
  }
  return null
}

/** The scheme (lower-cased, if any) and the host[:port] part of a URL or bare name. */
function splitInput(text: string): { scheme: string | null; hostPort: string } {
  let rest = text
  let scheme: string | null = null
  const match = SCHEME.exec(rest)
  if (match) {
    scheme = match[1].toLowerCase()
    rest = rest.slice(match[0].length)
  } else if (rest.startsWith("//")) {
    rest = rest.slice(2)
  }
  // Like browsers: the authority ends at "/", "\", "?" or "#", and the host
  // follows the last "@".
  const authority = rest.split(/[/\\?#]/, 1)[0]
  return { scheme, hostPort: authority.slice(authority.lastIndexOf("@") + 1) }
}

function isIpv6Like(hostPort: string): boolean {
  return hostPort.startsWith("[") || hostPort.split(":").length > 2
}

function toAscii(host: string): string {
  if (isAscii(host)) return host.toLowerCase()
  try {
    // The URL parser applies UTS 46 mapping and Punycode, like the API's
    // IDNA encoding: "Bücher.de" -> "xn--bcher-kva.de".
    return new URL(`http://${host}/`).hostname
  } catch {
    return host.toLowerCase()
  }
}

function isAscii(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) > 0x7f) return false
  }
  return true
}

function invalid(error: string): DomainCheck {
  return { ok: false, error }
}
