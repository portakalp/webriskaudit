"use client"

import { useState } from "react"
import { ScanWorkflow, WorkflowStep } from "@/components/ScanWorkflow"
import { DotGridBackground } from "@/components/dot-grid-background"
import { TrustFooter } from "@/components/trust-footer"
import { PricingSection } from "@/components/PricingSection"
import Image from "next/image"
import Link from "next/link"
import { ShieldCheck } from "lucide-react"

export default function Home() {
  const [workflowStep, setWorkflowStep] = useState<WorkflowStep>("form")

  return (
    <main className="relative min-h-screen flex flex-col overflow-hidden bg-[#F8FAFC]">
      <DotGridBackground />

      <header className="relative z-10 flex items-center justify-between p-4 md:p-6">
        <Link href="/" className="flex items-center gap-3 hover:opacity-80 transition-opacity" aria-label="Web Risk Audit - Home">
          <span className="text-xs md:text-sm font-semibold tracking-[0.2em] text-slate-800 uppercase">
            Web Risk Audit
          </span>
        </Link>
      </header>

      {/* Main content - 2 column split */}
      <div className="relative z-10 flex-1 flex items-center justify-center px-4 md:px-8 lg:px-16 py-8">
        <div className="w-full max-w-7xl grid grid-cols-1 lg:grid-cols-2 gap-8 lg:gap-16 items-center">
          <div className="hidden lg:flex flex-col items-center justify-center">
            <Image
              src="/images/hero-kale.png"
              alt="Digital security shield protecting email communications from threats"
              width={800}
              height={700}
              className="w-full max-w-2xl h-auto object-contain"
              style={{ minHeight: "60vh" }}
              priority
            />
            <p className="mt-6 text-xl md:text-2xl font-semibold text-slate-800 leading-relaxed max-w-xl text-center">
              Expert-Led Digital Asset Security Audits.{" "}
              <span className="text-slate-600">
                We provide evidence-based audits, severity ratings, and a prioritized remediation backlog. Implementation not included; your team applies the fixes.
              </span>
            </p>
          </div>

          <div className="w-full max-w-5xl mx-auto lg:mx-0 lg:ml-auto" id="contact-form">
            <div className="relative bg-white rounded-2xl p-8 md:p-10 shadow-2xl shadow-slate-900/10 overflow-hidden border border-slate-100">
              {/* Content */}
              <div className="relative z-10">
                {(workflowStep === "form" || workflowStep === "scanning") && (
                  <>
                    <h1 className="text-2xl md:text-3xl font-bold leading-tight text-center text-balance">
                      <span className="text-slate-900">Invisible Technical Risks are Costing You Clients.</span>{" "}
                      <span className="text-orange-500">Let's Find Them.</span>
                    </h1>

                    {/* Sub-headline */}
                    <p className="mt-4 text-sm text-slate-600 text-center text-pretty">
                      Don't let invisible errors bury your emails in spam or expose you to hackers. Get an expert-led technical audit today.
                    </p>
                  </>
                )}

                {/* Form */}
                <ScanWorkflow onStepChange={setWorkflowStep} />

                {/* Trust badges below form */}
                <div className="mt-6 flex flex-wrap justify-center gap-x-4 gap-y-2 text-xs text-slate-500">
                  <span className="flex items-center gap-1.5">
                    <svg className="w-3.5 h-3.5 text-emerald-500" fill="currentColor" viewBox="0 0 20 20">
                      <path
                        fillRule="evenodd"
                        d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                        clipRule="evenodd"
                      />
                    </svg>
                    No Credit Card Required
                  </span>
                  <span className="flex items-center gap-1.5">
                    <svg className="w-3.5 h-3.5 text-emerald-500" fill="currentColor" viewBox="0 0 20 20">
                      <path
                        fillRule="evenodd"
                        d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                        clipRule="evenodd"
                      />
                    </svg>
                    GDPR Compliant
                  </span>
                  <span className="flex items-center gap-1.5">
                    <svg className="w-3.5 h-3.5 text-emerald-500" fill="currentColor" viewBox="0 0 20 20">
                      <path
                        fillRule="evenodd"
                        d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                        clipRule="evenodd"
                      />
                    </svg>
                    AI + Human Analysis
                  </span>
                </div>

                <div className="mt-6 pt-6 border-t border-slate-100">
                  <p className="text-[10px] uppercase tracking-wider text-slate-400 text-center mb-3">
                    Audits compatibility with:
                  </p>
                  <div className="flex items-center justify-center gap-6">
                    {/* Google Workspace */}
                    <svg className="h-5 w-auto opacity-40 grayscale" viewBox="0 0 24 24" fill="currentColor">
                      <path
                        d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                        fill="#4285F4"
                      />
                      <path
                        d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                        fill="#34A853"
                      />
                      <path
                        d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                        fill="#FBBC05"
                      />
                      <path
                        d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                        fill="#EA4335"
                      />
                    </svg>
                    {/* Microsoft Outlook */}
                    <svg className="h-5 w-auto opacity-40 grayscale" viewBox="0 0 24 24" fill="currentColor">
                      <path
                        d="M24 7.387v10.478c0 .23-.08.424-.238.576-.158.154-.352.23-.58.23h-8.547v-6.959l1.6 1.229c.102.078.223.117.364.117.14 0 .263-.039.37-.117l6.793-5.206c.095-.063.168-.143.218-.238l.02-.11z"
                        fill="#0072C6"
                      />
                      <path
                        d="M24 5.5l-.02-.09c-.047-.088-.107-.164-.18-.23-.076-.064-.16-.11-.25-.138l-.064-.02h-8.85v4.078l1.6 1.229 6.79-5.207c.22-.167.357-.405.41-.688.006-.012.01-.025.01-.037V5.5h.554z"
                        fill="#0072C6"
                      />
                      <path
                        d="M8.82 9.238c-.52-.42-1.153-.63-1.9-.63-.75 0-1.38.21-1.89.63-.51.418-.764 1.014-.764 1.787 0 .774.254 1.372.763 1.793.51.42 1.14.63 1.89.63.75 0 1.383-.21 1.9-.63.52-.42.78-1.02.78-1.793 0-.773-.26-1.37-.78-1.787zm-1.9 3.17c-.4 0-.72-.12-.97-.36-.247-.24-.37-.57-.37-.99 0-.42.123-.75.37-.99.25-.24.57-.36.97-.36.4 0 .723.12.97.36.247.24.37.57.37.99 0 .42-.123.75-.37.99-.25.24-.57.36-.97.36z"
                        fill="#0072C6"
                      />
                      <path d="M14.634 3.373v18.254L0 19.328V5.672l14.634-2.299z" fill="#0072C6" />
                    </svg>
                    {/* Yahoo */}
                    <svg className="h-5 w-auto opacity-40 grayscale" viewBox="0 0 24 24" fill="currentColor">
                      <path
                        d="M10.816 8.81L7.89 15.297l-.13.375c-.12.39-.21.73-.27 1.017h-.018c-.06-.305-.14-.657-.23-1.057l-.1-.335L4.312 8.81H0l5.42 11.29-2.88 5.9h4.11l7.06-17.19h-2.894zM24 8.81h-3.55l-3.95 7.16h-.02l-.84-7.16h-3.47l1.86 10.06c.1.52.05.9-.18 1.14-.23.25-.64.37-1.22.37-.27 0-.54-.01-.81-.04v2.89c.47.06.95.09 1.42.09 1.51 0 2.64-.33 3.39-1 .75-.66 1.28-1.73 1.6-3.2L24 8.81z"
                        fill="#6001D2"
                      />
                    </svg>
                    {/* Cloudflare */}
                    <svg className="h-5 w-auto opacity-40 grayscale" viewBox="0 0 24 24" fill="currentColor">
                      <path
                        d="M16.509 16.155l.58-2.063c.066-.261.066-.496 0-.705a.944.944 0 00-.391-.509c-.183-.13-.405-.196-.666-.196h-9.35c-.065 0-.117-.026-.157-.078a.181.181 0 01-.013-.183c.013-.052.039-.091.078-.118.04-.026.091-.039.157-.039h9.506c.757 0 1.41-.248 1.958-.744.548-.496.887-1.136 1.018-1.919l.274-1.528a.258.258 0 00.013-.092 12.05 12.05 0 00-.013-.222.115.115 0 00-.052-.092c-.887-3.064-3.628-5.309-6.87-5.309-3.442 0-6.334 2.517-6.922 5.855a3.478 3.478 0 00-2.48-.065c-.848.287-1.514.848-1.997 1.684-.483.835-.666 1.736-.548 2.702h-.079c-1.135 0-2.102.404-2.898 1.214C.013 14.556 0 15.496 0 16.506v.261c0 .052.026.104.078.157.052.052.104.078.157.078h16.013c.065 0 .117-.026.157-.078a.181.181 0 01.013-.183l.091-.586z"
                        fill="#F38020"
                      />
                      <path
                        d="M19.883 9.508l-.13.013a.154.154 0 00-.13.091l-.418 1.45c-.066.261-.066.496 0 .705.053.209.17.379.391.509.183.13.405.196.666.196h2.454c.065 0 .117.026.157.078a.181.181 0 01.013.183c-.013.052-.039.091-.078.118-.04.026-.091.039-.156.039v-.327c0-1.475-.522-2.737-1.567-3.786-1.044-1.048-2.298-1.572-3.76-1.572h-.89z"
                        fill="#FAAE40"
                      />
                    </svg>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <PricingSection />

      <TrustFooter />
    </main>
  )
}
