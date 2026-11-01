import type { Metadata } from "next"
import Link from "next/link"
import { ArrowLeft } from "lucide-react"
import { openGraphDefaults, twitterDefaults } from "@/lib/metadata"

const title = "Privacy | WebRiskAudit"
const description =
  "How WebRiskAudit handles data: no accounts, no cookies, no analytics and no database of scans. Scanned domains appear in the API's logs."

export const metadata: Metadata = {
  title: "Privacy",
  description,
  alternates: {
    canonical: "/privacy-policy",
  },
  openGraph: {
    ...openGraphDefaults,
    title,
    description,
    url: "/privacy-policy",
  },
  twitter: {
    ...twitterDefaults,
    title,
    description,
  },
}

export default function PrivacyPolicyPage() {
  return (
    <div className="min-h-screen bg-slate-50">
      <div className="max-w-4xl mx-auto px-6 py-12">
        {/* Back to Home Link */}
        <Link
          href="/"
          className="inline-flex items-center gap-2 text-sm text-slate-600 hover:text-slate-900 transition-colors mb-6"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Home
        </Link>

        <div className="bg-white rounded-xl shadow-lg p-8 md:p-12">
          <h1 className="text-3xl md:text-4xl font-bold text-slate-900 mb-4">
            Privacy
          </h1>
          <p className="text-sm text-slate-500 mb-8">
            Last updated: 1 November 2026
          </p>

          <div className="max-w-none">
            <p className="text-slate-700 leading-relaxed mb-4">
              WebRiskAudit is an open-source, non-commercial project run by Taha Gökalp Bakar as an
              individual. This note describes what happens to data when you use webriskaudit.com.
            </p>

            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">What this site does not do</h2>
            <ul className="list-disc pl-6 space-y-2 text-slate-700 mb-4">
              <li>There are no accounts and nothing to sign up for.</li>
              <li>No cookies are set.</li>
              <li>There is no analytics, tracking or advertising.</li>
              <li>No data is sold or shared for marketing.</li>
            </ul>

            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">When you run a scan</h2>
            <p className="text-slate-700 leading-relaxed mb-4">
              The domain you enter is sent from your browser to the WebRiskAudit API. The API performs
              passive checks against that domain (DNS lookups, a TLS certificate check and HTTP requests for
              the home page and for up to about 50 common privacy-policy paths) and returns the result to your
              browser. The checks are made from the API server, so the scanned site sees the server&apos;s
              address, not yours.
            </p>
            <p className="text-slate-700 leading-relaxed mb-4">
              The API keeps no database of scans or results. Its application logs do record each scanned
              domain and the URLs requested while checking it, and these logs are stored by the API&apos;s
              hosting provider.
            </p>

            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">Hosting</h2>
            <p className="text-slate-700 leading-relaxed mb-4">
              The site is served through Cloudflare and the API runs on Render. Your browser connects to both
              directly, so each of them processes your IP address and request metadata (such as the time,
              requested URL and user agent) and keeps logs under its own privacy policy:{" "}
              <a
                href="https://www.cloudflare.com/privacypolicy/"
                className="text-orange-600 hover:text-orange-700 underline transition-colors"
              >
                Cloudflare
              </a>
              ,{" "}
              <a
                href="https://render.com/privacy"
                className="text-orange-600 hover:text-orange-700 underline transition-colors"
              >
                Render
              </a>
              . The API&apos;s application logs described above are stored by Render.
            </p>

            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">Source code</h2>
            <p className="text-slate-700 leading-relaxed mb-4">
              The code for the site and the API is public at{" "}
              <a
                href="https://github.com/portakalp/webriskaudit"
                className="text-orange-600 hover:text-orange-700 underline transition-colors"
              >
                github.com/portakalp/webriskaudit
              </a>
              , so you can check what it does.
            </p>

            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">Contact</h2>
            <p className="text-slate-700 leading-relaxed mb-4">
              For questions about this note, contact Taha Gökalp Bakar via{" "}
              <a
                href="https://github.com/portakalp"
                className="text-orange-600 hover:text-orange-700 underline transition-colors"
              >
                github.com/portakalp
              </a>
              . If this note changes, the date above is updated.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
