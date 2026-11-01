import { readFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import type { ScanReport } from "@/lib/types"

const root = join(dirname(fileURLToPath(import.meta.url)), "..")

/** public/sample-report.json, the report the site shows as its example. */
export const sampleReport = JSON.parse(
  readFileSync(join(root, "public", "sample-report.json"), "utf8"),
) as ScanReport
