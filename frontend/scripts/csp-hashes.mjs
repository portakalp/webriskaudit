// Puts the hashes of the static export's inline scripts into the site's Content
// Security Policy, so script-src needs no 'unsafe-inline'. Static hosting cannot
// add a per-request nonce and the scripts change with every build, so this runs
// right after next build (scripts/fill-csp-hashes.mjs, part of "pnpm build").
//
// Reads the placeholder from out/_headers (a copy of public/_headers) and
// nginx.conf, and writes out/_headers for Workers static assets and
// .next/nginx.conf for the Dockerfile. .next is not published, unlike out/.
// A problem throws, which fails the build: a policy without the right hashes
// would block the site's own scripts.
import { createHash } from "node:crypto"
import { readdirSync, readFileSync, writeFileSync } from "node:fs"
import { join } from "node:path"

import { JSDOM } from "jsdom"

/** Stands for the hashes in public/_headers and nginx.conf. */
export const PLACEHOLDER = "${SCRIPT_HASHES}"

/**
 * Cloudflare's limit for a line of _headers, spacing and header name included:
 * https://developers.cloudflare.com/workers/static-assets/headers/
 * Wrangler only warns about a longer line and drops it, so the site would lose
 * its whole CSP.
 */
export const MAX_HEADERS_LINE = 2000

// The type values a browser runs: the JavaScript MIME types, without parameters,
// and the inline types script-src also covers. Anything else is a data block,
// such as application/ld+json, which needs no hash.
// https://html.spec.whatwg.org/multipage/scripting.html#prepare-the-script-element
const SCRIPT_TYPES = new Set([
  "",
  "application/ecmascript",
  "application/javascript",
  "application/x-ecmascript",
  "application/x-javascript",
  "importmap",
  "module",
  "speculationrules",
  "text/ecmascript",
  "text/javascript",
  "text/javascript1.0",
  "text/javascript1.1",
  "text/javascript1.2",
  "text/javascript1.3",
  "text/javascript1.4",
  "text/javascript1.5",
  "text/jscript",
  "text/livescript",
  "text/x-ecmascript",
  "text/x-javascript",
])

/**
 * The text of each inline script of a page that a browser checks against
 * script-src. It comes from an HTML parser, so it is the text a browser hashes:
 * line endings normalized, entities left alone, ended where a browser ends it.
 *
 * @param {string} html
 * @returns {string[]}
 */
export function inlineScripts(html) {
  const { document } = new JSDOM(html).window
  return Array.from(document.querySelectorAll("script"))
    .filter((script) => {
      const type = (script.getAttribute("type") ?? "").trim().toLowerCase()
      return !script.hasAttribute("src") && SCRIPT_TYPES.has(type)
    })
    .map((script) => script.textContent)
    .filter((text) => text !== "") // Browsers skip these, but not whitespace-only scripts.
}

/**
 * The CSP source for a script: the SHA-256 of its text as UTF-8, in base64.
 *
 * @param {string} text
 * @returns {string}
 */
export function scriptHash(text) {
  return `'sha256-${createHash("sha256").update(text, "utf8").digest("base64")}'`
}

/** The unique hashes of the inline scripts of every HTML file under a directory, sorted. */
function collectHashes(directory) {
  const hashes = new Set()
  for (const file of readdirSync(directory, { recursive: true })) {
    if (!file.endsWith(".html")) continue
    for (const text of inlineScripts(readFileSync(join(directory, file), "utf8"))) {
      hashes.add(scriptHash(text))
    }
  }
  return [...hashes].sort()
}

/** A file's text with its one placeholder replaced by the hashes. */
function fillPlaceholder(path, hashes) {
  const parts = readFileSync(path, "utf8").split(PLACEHOLDER)
  if (parts.length !== 2) {
    throw new Error(`${path}: expected one ${PLACEHOLDER}, found ${parts.length - 1}`)
  }
  return parts.join(hashes.join(" "))
}

/**
 * Fills the hashes of root/out into root/out/_headers and root/.next/nginx.conf.
 * Nothing is written unless both files pass their checks.
 *
 * @param {string} root the frontend directory
 * @returns {string[]} the hashes
 */
export function fillCspHashes(root) {
  const out = join(root, "out")
  const hashes = collectHashes(out)
  if (hashes.length === 0) {
    throw new Error(`${out}: no inline scripts found, so there are no hashes for script-src`)
  }

  const headersPath = join(out, "_headers")
  const headers = fillPlaceholder(headersPath, hashes)
  const nginx = fillPlaceholder(join(root, "nginx.conf"), hashes)

  const tooLong = headers.split("\n").find((line) => line.length > MAX_HEADERS_LINE)
  if (tooLong !== undefined) {
    throw new Error(
      `${headersPath}: a line has ${tooLong.length} characters, over Cloudflare's limit of ` +
        `${MAX_HEADERS_LINE}: ${tooLong.slice(0, 60)}...`,
    )
  }

  writeFileSync(headersPath, headers)
  writeFileSync(join(root, ".next", "nginx.conf"), nginx)
  return hashes
}
