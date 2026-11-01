import type { Metadata } from "next"
import Link from "next/link"
import { ArrowLeft } from "lucide-react"

export const metadata: Metadata = {
  title: "Privacy Policy | Web Risk Audit",
  description: "Learn how Web Risk Audit collects, uses, and protects your personal data in compliance with GDPR/RODO regulations.",
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

        {/* Privacy Policy Content */}
        <div className="bg-white rounded-xl shadow-lg p-8 md:p-12">
          <h1 className="text-3xl md:text-4xl font-bold text-slate-900 mb-4">
            Privacy Policy
          </h1>
          <p className="text-sm text-slate-500 mb-8">
            Last Updated: {new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}
          </p>

          {/* Policy Content */}
          <div className="prose prose-slate max-w-none">
            {/* 1. Introduction */}
            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">1. Introduction</h2>
            <p className="text-slate-700 leading-relaxed mb-4">
              Web Risk Audit ("we," "our," or "us") is committed to protecting your privacy and personal data.
              This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you
              visit our website and use our security audit services.
            </p>

            {/* 2. Data Collection */}
            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">2. Data We Collect</h2>
            <p className="text-slate-700 leading-relaxed mb-4">We collect the following types of information:</p>
            <ul className="list-disc pl-6 space-y-2 text-slate-700 mb-4">
              <li><strong>Contact Information:</strong> Email addresses you provide when requesting a security audit report.</li>
              <li><strong>Domain Information:</strong> Domain names you submit for security analysis.</li>
              <li><strong>Technical Data:</strong> IP addresses, browser types, device information, and cookies for analytics and functionality.</li>
              <li><strong>Usage Data:</strong> Pages visited, time spent on site, and interaction patterns.</li>
            </ul>

            {/* 3. How We Use Your Data */}
            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">3. How We Use Your Data</h2>
            <p className="text-slate-700 leading-relaxed mb-4">We use your personal data for the following purposes:</p>
            <ul className="list-disc pl-6 space-y-2 text-slate-700 mb-4">
              <li>Conducting security audits on domains you submit</li>
              <li>Delivering audit reports to your provided email address</li>
              <li>Scheduling diagnosis calls via Calendly (third-party service)</li>
              <li>Improving our website and services through analytics</li>
              <li>Complying with legal obligations</li>
            </ul>

            {/* 4. Cookies */}
            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">4. Cookies and Tracking Technologies</h2>
            <p className="text-slate-700 leading-relaxed mb-4">
              We use cookies and similar tracking technologies to enhance your browsing experience. These include:
            </p>
            <ul className="list-disc pl-6 space-y-2 text-slate-700 mb-4">
              <li><strong>Essential Cookies:</strong> Required for basic site functionality (e.g., remembering your cookie consent choice).</li>
              <li><strong>Analytics Cookies:</strong> Help us understand how visitors interact with our website (e.g., Cloudflare Analytics).</li>
            </ul>
            <p className="text-slate-700 leading-relaxed mb-4">
              You can control cookies through your browser settings. Note that disabling cookies may affect site functionality.
            </p>

            {/* 5. Third-Party Services */}
            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">5. Third-Party Services</h2>
            <p className="text-slate-700 leading-relaxed mb-4">We use the following third-party services that may collect your data:</p>
            <ul className="list-disc pl-6 space-y-2 text-slate-700 mb-4">
              <li><strong>Calendly:</strong> For scheduling diagnosis calls. Calendly's privacy policy applies to data collected through their service.</li>
              <li><strong>Cloudflare:</strong> For website hosting and security. Cloudflare may process technical data for CDN and security purposes.</li>
              <li><strong>Render.com:</strong> Backend API hosting for security audit processing.</li>
            </ul>

            {/* 6. Your Rights (GDPR/RODO) */}
            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">6. Your Data Rights</h2>
            <p className="text-slate-700 leading-relaxed mb-4">Under GDPR/RODO, you have the following rights regarding your personal data:</p>
            <ul className="list-disc pl-6 space-y-2 text-slate-700 mb-4">
              <li><strong>Right to Access:</strong> Request a copy of your personal data we hold.</li>
              <li><strong>Right to Rectification:</strong> Request correction of inaccurate data.</li>
              <li><strong>Right to Erasure:</strong> Request deletion of your data ("right to be forgotten").</li>
              <li><strong>Right to Data Portability:</strong> Request your data in a machine-readable format.</li>
              <li><strong>Right to Object:</strong> Object to processing of your data for specific purposes.</li>
              <li><strong>Right to Withdraw Consent:</strong> Withdraw consent for data processing at any time.</li>
            </ul>
            <p className="text-slate-700 leading-relaxed mb-4">
              To exercise any of these rights, please contact us at the email address below.
            </p>

            {/* 7. Data Retention */}
            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">7. Data Retention</h2>
            <p className="text-slate-700 leading-relaxed mb-4">
              We retain your personal data only for as long as necessary to fulfill the purposes outlined in this policy:
            </p>
            <ul className="list-disc pl-6 space-y-2 text-slate-700 mb-4">
              <li>Audit reports and associated email addresses: 12 months</li>
              <li>Analytics data: Aggregated and anonymized after 6 months</li>
              <li>Cookie consent records: Until withdrawn by user</li>
            </ul>

            {/* 8. Data Security */}
            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">8. Data Security</h2>
            <p className="text-slate-700 leading-relaxed mb-4">
              We implement appropriate technical and organizational measures to protect your data, including:
            </p>
            <ul className="list-disc pl-6 space-y-2 text-slate-700 mb-4">
              <li>256-bit SSL encryption for data transmission</li>
              <li>Secure cloud hosting with Cloudflare and Render</li>
              <li>Regular security audits and vulnerability assessments</li>
              <li>Access controls and authentication for internal systems</li>
            </ul>
            <p className="text-slate-700 leading-relaxed mb-4">
              However, no method of transmission over the internet is 100% secure. We cannot guarantee absolute security.
            </p>

            {/* 9. International Data Transfers */}
            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">9. International Data Transfers</h2>
            <p className="text-slate-700 leading-relaxed mb-4">
              Your data may be transferred to and processed in countries outside the European Economic Area (EEA).
              We ensure appropriate safeguards are in place, such as standard contractual clauses approved by the European Commission.
            </p>

            {/* 10. Children's Privacy */}
            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">10. Children's Privacy</h2>
            <p className="text-slate-700 leading-relaxed mb-4">
              Our services are not intended for individuals under the age of 18. We do not knowingly collect personal
              data from children. If you believe we have inadvertently collected data from a minor, please contact us immediately.
            </p>

            {/* 11. Changes to This Policy */}
            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">11. Changes to This Privacy Policy</h2>
            <p className="text-slate-700 leading-relaxed mb-4">
              We may update this Privacy Policy from time to time to reflect changes in our practices or legal requirements.
              We will notify you of significant changes by posting the updated policy on this page with a new "Last Updated" date.
            </p>

            {/* 12. Contact Information */}
            <h2 className="text-2xl font-bold text-slate-900 mt-8 mb-4">12. Contact Us</h2>
            <p className="text-slate-700 leading-relaxed mb-4">
              If you have questions about this Privacy Policy or wish to exercise your data rights, please contact us:
            </p>
            <div className="bg-slate-50 border-2 border-slate-200 rounded-lg p-6 my-6">
              <p className="font-semibold text-slate-900 mb-3">Mosaic Mutiny Ltd</p>

              <p className="text-slate-700 mb-2">
                <strong>Registration Number:</strong> 16532268 (Registered in England & Wales)
              </p>

              <p className="text-slate-700 mb-2">
                <strong className="text-slate-900">ICO Registration Reference:</strong>{" "}
                <span className="font-semibold text-slate-900">CSN1288095</span>
              </p>

              <p className="text-slate-700 mb-2">
                <strong>Registered Office:</strong>{" "}
                <span className="text-slate-900">
                  71-75 Shelton Street, Covent Garden, London, United Kingdom, WC2H 9JQ
                </span>
              </p>

              <p className="text-slate-700">
                <strong>Contact Email:</strong>{" "}
                <a
                  href="mailto:info@webriskaudit.com"
                  className="text-orange-600 hover:text-orange-700 underline transition-colors"
                >
                  info@webriskaudit.com
                </a>
              </p>
            </div>

            {/* Footer Note */}
            <p className="text-sm text-slate-500 mt-8 pt-8 border-t border-slate-200">
              This Privacy Policy is effective as of the date listed above and applies to all users of our website and services.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
