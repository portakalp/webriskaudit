// @vitest-environment node
import { describe, expect, it } from "vitest"
import { normalizeDomain, validateDomain } from "./validation"

const IP_ADDRESS = "IP addresses cannot be scanned; enter a domain name."
const BAD_LABEL =
  "Each part of a domain name must be 1-63 letters, digits or hyphens and cannot start or end with a hyphen."

describe("normalizeDomain", () => {
  it.each([
    ["example.com", "example.com"],
    ["  Example.COM  ", "example.com"],
    ["https://www.example.com/path?q=1#top", "www.example.com"],
    ["HTTP://Example.com", "example.com"],
    ["http://user:secret@example.com:8080/", "example.com"],
    ["https://other.example@example.com", "example.com"],
    ["example.com:443", "example.com"],
    ["example.com.", "example.com"],
    ["//example.com/path", "example.com"],
    ["example.com\\path", "example.com"],
    ["Bücher.de", "xn--bcher-kva.de"],
  ])("normalizes %j to %j", (input, expected) => {
    expect(normalizeDomain(input)).toBe(expected)
  })

  it("keeps www. because the API scans the host as given", () => {
    expect(normalizeDomain("https://www.example.com/")).toBe("www.example.com")
  })
})

describe("validateDomain", () => {
  it("returns the normalized domain for valid input", () => {
    expect(validateDomain(" https://WWW.Example.com:443/about ")).toEqual({ ok: true, domain: "www.example.com" })
  })

  it("accepts internationalized names in their ASCII form", () => {
    expect(validateDomain("пример.рф")).toEqual({ ok: true, domain: "xn--e1afmkfd.xn--p1ai" })
  })

  it.each([
    ["empty input", "", "Enter a domain name such as example.com."],
    ["blank input", "   ", "Enter a domain name such as example.com."],
    ["a scheme without a host", "https://", "Enter a domain name such as example.com."],
    ["a single label", "localhost", "Enter a full domain name such as example.com."],
    ["another scheme", "ftp://example.com", "Only http and https URLs are supported."],
    ["an IPv4 address", "192.168.0.1", IP_ADDRESS],
    ["a short IPv4 form", "127.1", IP_ADDRESS],
    ["a hex IPv4 form", "0x7f.1", IP_ADDRESS],
    ["a bracketed IPv6 address", "[::1]", IP_ADDRESS],
    ["an IPv6 URL", "http://[2001:db8::1]:443/", IP_ADDRESS],
    ["a port out of range", "example.com:99999", "The port number is not valid."],
    ["a non-numeric port", "example.com:http", "The port number is not valid."],
    ["a leading hyphen", "-example.com", BAD_LABEL],
    ["an underscore", "exa_mple.com", BAD_LABEL],
    ["an empty label", "example..com", BAD_LABEL],
    ["a 64-character label", `${"a".repeat(64)}.com`, BAD_LABEL],
    ["a 259-character name", `${`${"a".repeat(63)}.`.repeat(4)}com`, "The domain name is longer than 253 characters."],
    ["2049 characters of input", "a".repeat(2049), "The input is too long to be a domain name."],
  ])("rejects %s", (_case, input, error) => {
    expect(validateDomain(input)).toEqual({ ok: false, error })
  })
})
