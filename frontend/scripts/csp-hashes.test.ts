// @vitest-environment node
import { createHash } from "node:crypto"
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join } from "node:path"
import { afterEach, beforeEach, describe, expect, it } from "vitest"

import { fillCspHashes, inlineScripts, MAX_HEADERS_LINE, PLACEHOLDER, scriptHash } from "./csp-hashes.mjs"

const page = (body: string) => `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>${body}</body></html>`

describe("inlineScripts", () => {
  it("finds inline scripts in the head and the body, in order", () => {
    const html = "<html><head><script>first()</script></head><body><script>second()</script></body></html>"

    expect(inlineScripts(html)).toEqual(["first()", "second()"])
  })

  it("skips scripts with src, even with a body or an empty value", () => {
    const html = page(`
      <script src="/_next/static/chunks/a.js" async=""></script>
      <script src="/b.js">ignored()</script>
      <script src="">ignored()</script>
    `)

    expect(inlineScripts(html)).toEqual([])
  })

  it("skips JSON data blocks", () => {
    const html = page(`
      <script type="application/ld+json">{"@type":"WebApplication"}</script>
      <script type="application/json">{}</script>
      <script type="text/plain">not code</script>
      <script type="text/javascript; charset=utf-8">not run by browsers</script>
    `)

    expect(inlineScripts(html)).toEqual([])
  })

  it("keeps every type a browser runs, in any case and with surrounding spaces", () => {
    const html = page(`
      <script type="">a()</script>
      <script type="text/javascript">b()</script>
      <script type="application/javascript">c()</script>
      <script type="module">d()</script>
      <script type=" TEXT/JavaScript ">e()</script>
      <script type="importmap">{"imports":{}}</script>
      <script type="speculationrules">{"prefetch":[]}</script>
      <script type="webbundle">{"source":"/a.wbn"}</script>
    `)

    expect(inlineScripts(html)).toEqual([
      "a()",
      "b()",
      "c()",
      "d()",
      "e()",
      '{"imports":{}}',
      '{"prefetch":[]}',
      '{"source":"/a.wbn"}',
    ])
  })

  it("skips empty scripts but keeps whitespace-only ones, which browsers still check", () => {
    expect(inlineScripts(page("<script></script><script> \n</script>"))).toEqual([" \n"])
  })

  it("keeps a multi-line body byte for byte", () => {
    const body = "\n  const a = 1;\n\n\tconst b = 2;  \n"

    expect(inlineScripts(page(`<script>${body}</script>`))).toEqual([body])
  })

  it("normalizes line endings as the HTML parser does", () => {
    expect(inlineScripts(page("<script>a()\r\nb()\rc()</script>"))).toEqual(["a()\nb()\nc()"])
  })

  it("leaves entities alone, because script text is not decoded", () => {
    expect(inlineScripts(page("<script>a &amp;&amp; b()</script>"))).toEqual(["a &amp;&amp; b()"])
  })

  it("reads a script up to the end tag a browser sees", () => {
    const body = 'a("<\\/script>"); /* </scriptx> */'
    const html = page(`<script>${body}</script ><script><!-- <script> </script> --></script>`)

    expect(inlineScripts(html)).toEqual([body, "<!-- <script> </script> -->"])
  })

  it("skips markup that is not a script element", () => {
    const html = page("<!-- <script>a()</script> --><template><script>b()</script></template>")

    expect(inlineScripts(html)).toEqual([])
  })
})

describe("scriptHash", () => {
  it("matches the example in the CSP specification", () => {
    expect(scriptHash("alert('Hello, world.');")).toBe("'sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng='")
  })

  it("hashes the UTF-8 bytes of the text", () => {
    const text = 'self.__next_f.push([1,"Gökalp – ✓"])'
    const digest = createHash("sha256").update(Buffer.from(text, "utf8")).digest("base64")

    expect(scriptHash(text)).toBe(`'sha256-${digest}'`)
    expect(scriptHash(text)).not.toBe(scriptHash(text.normalize("NFD")))
  })
})

describe("fillCspHashes", () => {
  const headersTemplate = `# A comment\n/*\n  Content-Security-Policy: script-src 'self' ${PLACEHOLDER}; style-src 'self'\n`
  const nginxTemplate = `add_header Content-Security-Policy "script-src 'self' ${PLACEHOLDER}; connect-src 'self' \${API_ORIGIN};" always;\n`

  let root: string

  const write = (path: string, text: string) => {
    mkdirSync(dirname(join(root, path)), { recursive: true })
    writeFileSync(join(root, path), text)
  }
  const read = (path: string) => readFileSync(join(root, path), "utf8")

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "csp-hashes-"))
    mkdirSync(join(root, ".next"))
    write("out/_headers", headersTemplate)
    write("nginx.conf", nginxTemplate)
    write("out/index.html", page("<script>b()</script><script>a()</script>"))
    write("out/nested/page/index.html", page("<script>a()</script><script>c()</script>"))
    write("out/notes.txt", page("<script>not.html()</script>"))
  })

  afterEach(() => {
    rmSync(root, { recursive: true, force: true })
  })

  it("fills the sorted, unique hashes of every HTML file into both files", () => {
    const expected = ["a()", "b()", "c()"].map(scriptHash).sort()

    const hashes = fillCspHashes(root)

    expect(hashes).toEqual(expected)
    expect(read("out/_headers")).toBe(headersTemplate.replace(PLACEHOLDER, expected.join(" ")))
    expect(read(".next/nginx.conf")).toBe(nginxTemplate.replace(PLACEHOLDER, expected.join(" ")))
  })

  it("leaves the template and the API origin placeholder of nginx.conf alone", () => {
    fillCspHashes(root)

    expect(read("nginx.conf")).toBe(nginxTemplate)
    expect(read(".next/nginx.conf")).toContain("connect-src 'self' ${API_ORIGIN};")
  })

  it("fails when _headers has no placeholder", () => {
    write("out/_headers", "/*\n  Content-Security-Policy: script-src 'self'\n")

    expect(() => fillCspHashes(root)).toThrow(/_headers: expected one \$\{SCRIPT_HASHES\}, found 0/)
  })

  it("fails when nginx.conf has no placeholder, and writes nothing", () => {
    write("nginx.conf", "server {}\n")

    expect(() => fillCspHashes(root)).toThrow(/nginx\.conf: expected one \$\{SCRIPT_HASHES\}, found 0/)
    expect(read("out/_headers")).toBe(headersTemplate)
  })

  it("fails when a file has the placeholder twice", () => {
    write("out/_headers", `${headersTemplate}# ${PLACEHOLDER}\n`)

    expect(() => fillCspHashes(root)).toThrow(/found 2/)
  })

  it("fails when no page has an inline script", () => {
    write("out/index.html", page('<script src="/a.js"></script>'))
    write("out/nested/page/index.html", page('<script type="application/ld+json">{}</script>'))

    expect(() => fillCspHashes(root)).toThrow(/no inline scripts found/)
    expect(read("out/_headers")).toBe(headersTemplate)
  })

  it("fails when there are no pages", () => {
    rmSync(join(root, "out/index.html"))
    rmSync(join(root, "out/nested"), { recursive: true })

    expect(() => fillCspHashes(root)).toThrow(/no inline scripts found/)
  })

  it("accepts a line of exactly the limit and fails on one more character", () => {
    write("out/index.html", page("<script>a()</script>"))
    rmSync(join(root, "out/nested"), { recursive: true })
    const prefix = "  Content-Security-Policy: script-src 'self' "
    const room = MAX_HEADERS_LINE - prefix.length - scriptHash("a()").length

    write("out/_headers", `${prefix}${PLACEHOLDER}${"x".repeat(room)}\n`)
    expect(() => fillCspHashes(root)).not.toThrow()

    write("out/_headers", `${prefix}${PLACEHOLDER}${"x".repeat(room + 1)}\n`)
    expect(() => fillCspHashes(root)).toThrow(/a line has 2001 characters, over Cloudflare's limit of 2000/)
  })
})
