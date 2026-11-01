import type { Metadata } from "next"
import Link from "next/link"
import { ArrowLeft } from "lucide-react"
import { openGraphDefaults, twitterDefaults } from "@/lib/metadata"

const title = "Privacy | WebRiskAudit"
const description =
  "How WebRiskAudit handles data: no accounts, no cookies, no analytics and no database of scans. Scanned domains appear in the API's logs for 14 days."

const LINK = "text-orange-700 hover:text-orange-800 underline underline-offset-2 transition-colors"

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
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <main className="max-w-4xl mx-auto px-4 py-12 sm:px-6">
        {/* Back to Home Link */}
        <Link
          href="/"
          className="inline-flex items-center gap-2 rounded text-sm text-slate-700 hover:text-slate-900 transition-colors mb-6"
        >
          <ArrowLeft className="w-4 h-4" aria-hidden="true" />
          Back to Home
        </Link>

        <div className="bg-white rounded-xl shadow-lg p-6 sm:p-8 md:p-12">
          <h1 className="text-3xl md:text-4xl font-bold text-slate-900 mb-4">
            Privacy
          </h1>
          <p className="text-sm text-slate-600 mb-8">
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
              The domain you enter is sent from your browser to the WebRiskAudit API, which checks it with
              passive requests only: DNS lookups (the domain&apos;s addresses and its SPF, DMARC and DKIM
              records), one TLS handshake on port 443 to read the certificate, and HTTP GET requests for the
              http:// and https:// home page, following up to 5 redirects. Nothing else is requested: no link
              crawling, port scanning or login attempts. The requests are made from the API server and name
              WebRiskAudit in their user agent, so the scanned site sees the server&apos;s address, not yours.
              The DNS lookups go through the public resolvers of Cloudflare (1.1.1.1) and Quad9 (9.9.9.10),
              which see the domain but not your IP address and handle it under their own privacy policies (
              <a href="https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/" className={LINK}>
                Cloudflare
              </a>
              ,{" "}
              <a href="https://quad9.net/privacy/policy/" className={LINK}>
                Quad9
              </a>
              ).
            </p>
            <p className="text-slate-700 leading-relaxed mb-4">
              The API keeps no database of scans. A finished report is answered from the API&apos;s memory for
              10 minutes, so repeated scans of the same domain use that cache, and dropped after that. For
              each scan request, the API&apos;s application log records the domain, the outcome, the score, grade
              and coverage, whether the report came from the cache, and how long the request waited and took.
              IP addresses are not logged. If a scan fails unexpectedly, the error is logged together with the
              domain. How long these logs are kept is described under Hosting.
            </p>
            <p className="text-slate-700 leading-relaxed mb-4">
              To limit abuse, the API counts recent scans in its memory per IPv4 address, or per IPv6 /64
              network (the block of addresses one connection usually gets): by default 10 scans per 10 minutes,
              and one at a time, for which the address or network is also kept while its scan runs. These counts
              are never written to the logs or to disk. They are dropped with the first request the API handles
              after the last counted scan is 10 minutes old (the hosting platform&apos;s health check alone sends
              one every 30 seconds), or when the API restarts.
            </p>

            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">Hosting</h2>
            <p className="text-slate-700 leading-relaxed mb-4">
              The site and the API are both served through Cloudflare. Your browser connects only to
              Cloudflare, which delivers the site&apos;s files itself and forwards scan requests to the API.
              Cloudflare processes your IP address and request details (such as the time, the requested URL
              and your browser&apos;s user agent) to deliver and protect both, including a limit on scan requests
              per IP address, and keeps logs as described in its{" "}
              <a href="https://www.cloudflare.com/privacypolicy/" className={LINK}>
                privacy policy
              </a>
              .
            </p>
            <p className="text-slate-700 leading-relaxed mb-4">
              The API runs on Google Cloud Run in Google&apos;s europe-west1 region (Belgium), behind a Google
              load balancer. The load balancer is global, so a request can enter Google&apos;s network outside the
              EU. Cloudflare passes your IP address to the API in a request header, and the API uses it only in
              memory, for the limits described above. The load balancer&apos;s request logs are switched off, and
              Cloud Run&apos;s request logs, which would contain your IP address, are excluded and not stored. The
              application logs described above are kept for 14 days in a log bucket in europe-west1. An
              unexpected error, with the domain but without an IP address, can also be kept for up to 30 days by
              Google Cloud&apos;s Error Reporting. Google processes this data as a processor under the{" "}
              <a href="https://cloud.google.com/terms/data-processing-addendum" className={LINK}>
                Cloud Data Processing Addendum
              </a>
              ; see also the{" "}
              <a href="https://cloud.google.com/terms/cloud-privacy-notice" className={LINK}>
                Google Cloud Privacy Notice
              </a>
              .
            </p>
            <p className="text-slate-700 leading-relaxed mb-4">
              Cloudflare and Google are US companies, so your data may be processed outside the EU. Cloudflare,
              Inc. and Google LLC are certified under the EU-U.S. Data Privacy Framework, and both companies
              also rely on standard contractual clauses for such transfers.
            </p>

            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">Source code</h2>
            <p className="text-slate-700 leading-relaxed mb-4">
              The code for the site and the API is public at{" "}
              <a href="https://github.com/portakalp/webriskaudit" className={LINK}>
                github.com/portakalp/webriskaudit
              </a>
              , so you can check what it does.
            </p>

            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">Contact</h2>
            <p className="text-slate-700 leading-relaxed mb-4">
              For questions about this note, contact Taha Gökalp Bakar via{" "}
              <a href="https://github.com/portakalp" className={LINK}>
                github.com/portakalp
              </a>
              . If this note changes, the date above is updated.
            </p>
          </div>
        </div>
      </main>
    </div>
  )
}
