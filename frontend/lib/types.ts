export type RiskLevel = "SECURE" | "MODERATE" | "CRITICAL"

export interface CategoryScore {
  score: number
  max: number
  percentage: number
  risk_level: RiskLevel
  tests: string[]
}

// Response body of POST /api/scan
export interface ScanResult {
  domain: string
  score: number
  risk_level: RiskLevel

  // Email & Reputation
  spf_status: boolean
  dkim_status: boolean
  dmarc_status: boolean
  blacklist_status: boolean // true = not listed

  // Server Security
  waf_status: boolean
  ssl_status: boolean
  server_leak: boolean // true = server banner discloses software
  security_headers_score: number // required security headers present, 0-5

  // Compliance
  compliance_risk: boolean // true = no privacy policy found

  email_security: CategoryScore
  server_security: CategoryScore
  compliance: CategoryScore
}
