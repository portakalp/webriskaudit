// API types, derived from the generated lib/api-types.ts (run "pnpm gen:api"
// after backend/openapi.json changes). Nothing here is written by hand.
import type { components, paths } from "./api-types"

type Schemas = components["schemas"]
type ScanOperation = paths["/api/v1/scan"]["post"]

export type ScanRequest = ScanOperation["requestBody"]["content"]["application/json"]
export type ScanReport = ScanOperation["responses"][200]["content"]["application/json"]
export type ProblemDetails = ScanOperation["responses"][422]["content"]["application/problem+json"]

export type CheckResult = Schemas["CheckResult"]
export type CategorySummary = Schemas["CategorySummary"]
export type Category = Schemas["Category"]
export type Status = Schemas["Status"]
export type Evidence = Schemas["Evidence"]
export type Reference = Schemas["Reference"]
export type Coverage = Schemas["Coverage"]
export type Grade = NonNullable<ScanReport["grade"]>
