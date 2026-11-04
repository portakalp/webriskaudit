"use client"

import { useState } from "react"
import Image from "next/image"
import Link from "next/link"
import { ScanWorkflow, type WorkflowStep } from "@/components/ScanWorkflow"
import { DotGridBackground } from "@/components/dot-grid-background"
import { SiteFooter } from "@/components/site-footer"

export default function Home() {
  const [workflowStep, setWorkflowStep] = useState<WorkflowStep>("form")
  // The report takes the full content width instead of the half-width card
  const showReport = workflowStep === "report"

  return (
    <div className="relative flex min-h-screen flex-col overflow-hidden bg-[#F8FAFC]">
      <DotGridBackground />

      <header className="relative z-10 flex items-center justify-between p-4 md:p-6">
        <Link href="/" className="rounded transition-opacity hover:opacity-80" aria-label="WebRiskAudit home">
          <span className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-800 md:text-sm">
            WebRiskAudit
          </span>
        </Link>
        <a
          href="https://github.com/portakalp/webriskaudit"
          className="rounded text-xs font-medium text-slate-700 transition-colors hover:text-slate-900 md:text-sm"
        >
          GitHub
        </a>
      </header>

      <main className="relative z-10 flex flex-1 items-center justify-center px-4 py-8 md:px-8 lg:px-16">
        <div
          className={`grid w-full max-w-7xl grid-cols-1 items-center gap-8 lg:gap-16 ${showReport ? "" : "lg:grid-cols-2"}`}
        >
          {!showReport && (
            <div className="hidden flex-col items-center justify-center lg:flex">
              <Image
                src="/images/hero-kale.png"
                alt="WebRiskAudit logo"
                width={800}
                height={700}
                className="h-auto w-full max-w-2xl object-contain"
                style={{ minHeight: "60vh" }}
                priority
              />
              <p className="mt-6 max-w-xl text-center text-xl font-semibold leading-relaxed text-slate-800 md:text-2xl">
                An open-source passive security scanner.{" "}
                <span className="text-slate-600">
                  It reads the public signals a domain already exposes and shows the evidence it records.
                </span>
              </p>
            </div>
          )}

          <div className={showReport ? "w-full" : "mx-auto w-full max-w-5xl lg:mx-0 lg:ml-auto"}>
            <div className="relative overflow-hidden rounded-2xl border border-slate-100 bg-white p-5 text-slate-900 shadow-2xl shadow-slate-900/10 sm:p-8 md:p-10">
              <h1
                className={
                  showReport
                    ? "sr-only"
                    : "text-balance text-center text-2xl font-bold leading-tight text-slate-900 md:text-3xl"
                }
              >
                Security posture check for a domain
              </h1>
              {!showReport && (
                <p className="mt-4 text-pretty text-center text-sm text-slate-700">
                  Checks email authentication (SPF, DMARC, DKIM), the TLS certificate, the redirect from HTTP to
                  HTTPS, HSTS and other HTTP security headers, and cookie flags. Where a check records evidence, the
                  report shows it.
                </p>
              )}

              <ScanWorkflow onStepChange={setWorkflowStep} />

              <p className="mt-6 text-pretty border-t border-slate-100 pt-6 text-center text-xs text-slate-600">
                Only passive checks are performed: DNS lookups, a TLS handshake to read the certificate and HTTP GET
                requests for the http:// and https:// home page, following up to 5 redirects. Results are automated
                and heuristic, and are not a substitute for a professional security assessment.
              </p>
            </div>
          </div>
        </div>
      </main>

      <SiteFooter />
    </div>
  )
}
