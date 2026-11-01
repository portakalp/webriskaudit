"use client"

import { useState } from "react"
import { ScanWorkflow, WorkflowStep } from "@/components/ScanWorkflow"
import { DotGridBackground } from "@/components/dot-grid-background"
import { SiteFooter } from "@/components/site-footer"
import Image from "next/image"
import Link from "next/link"

export default function Home() {
  const [workflowStep, setWorkflowStep] = useState<WorkflowStep>("form")

  return (
    <main className="relative min-h-screen flex flex-col overflow-hidden bg-[#F8FAFC]">
      <DotGridBackground />

      <header className="relative z-10 flex items-center justify-between p-4 md:p-6">
        <Link href="/" className="flex items-center gap-3 hover:opacity-80 transition-opacity" aria-label="WebRiskAudit - Home">
          <span className="text-xs md:text-sm font-semibold tracking-[0.2em] text-slate-800 uppercase">
            WebRiskAudit
          </span>
        </Link>
        <a
          href="https://github.com/portakalp/webriskaudit"
          className="text-xs md:text-sm font-medium text-slate-600 hover:text-slate-900 transition-colors"
        >
          GitHub
        </a>
      </header>

      {/* Main content - 2 column split */}
      <div className="relative z-10 flex-1 flex items-center justify-center px-4 md:px-8 lg:px-16 py-8">
        <div className="w-full max-w-7xl grid grid-cols-1 lg:grid-cols-2 gap-8 lg:gap-16 items-center">
          <div className="hidden lg:flex flex-col items-center justify-center">
            <Image
              src="/images/hero-kale.png"
              alt="WebRiskAudit logo"
              width={800}
              height={700}
              className="w-full max-w-2xl h-auto object-contain"
              style={{ minHeight: "60vh" }}
              priority
            />
            <p className="mt-6 text-xl md:text-2xl font-semibold text-slate-800 leading-relaxed max-w-xl text-center">
              An open-source passive security scanner.{" "}
              <span className="text-slate-600">
                It reads the public signals a domain already exposes and summarizes them in a single score.
              </span>
            </p>
          </div>

          <div className="w-full max-w-5xl mx-auto lg:mx-0 lg:ml-auto">
            <div className="relative bg-white rounded-2xl p-8 md:p-10 shadow-2xl shadow-slate-900/10 overflow-hidden border border-slate-100">
              {/* Content */}
              <div className="relative z-10">
                {(workflowStep === "form" || workflowStep === "scanning") && (
                  <>
                    <h1 className="text-2xl md:text-3xl font-bold leading-tight text-center text-balance text-slate-900">
                      Security posture check for a domain
                    </h1>

                    {/* Sub-headline */}
                    <p className="mt-4 text-sm text-slate-600 text-center text-pretty">
                      Checks email authentication (SPF, DKIM, DMARC), DNS blocklists, the TLS certificate,
                      HTTP security headers, the server banner, CDN or WAF presence and a privacy policy page.
                    </p>
                  </>
                )}

                {/* Form */}
                <ScanWorkflow onStepChange={setWorkflowStep} />

                <p className="mt-6 pt-6 border-t border-slate-100 text-xs text-slate-500 text-center text-pretty">
                  Only passive checks are performed: DNS lookups, one TLS handshake and a few ordinary HTTP GET
                  requests. Results are automated and heuristic, and are not a substitute for a professional
                  security assessment.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <SiteFooter />
    </main>
  )
}
