// The step of "pnpm build" after next build; see csp-hashes.mjs.
import { fileURLToPath } from "node:url"

import { fillCspHashes } from "./csp-hashes.mjs"

const hashes = fillCspHashes(fileURLToPath(new URL("..", import.meta.url)))
console.log(`CSP: ${hashes.length} script hashes in out/_headers and .next/nginx.conf`)
