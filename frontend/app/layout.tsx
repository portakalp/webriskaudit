import type React from "react"
import type { Metadata } from "next"
import { Plus_Jakarta_Sans, JetBrains_Mono } from "next/font/google"
import "./globals.css"

const _plusJakartaSans = Plus_Jakarta_Sans({ subsets: ["latin"] })
const _jetbrainsMono = JetBrains_Mono({ subsets: ["latin"] })

export const metadata: Metadata = {
  metadataBase: new URL("https://webriskaudit.com"),
  title: {
    default: "WebRiskAudit | Open-source passive security scanner",
    template: "%s | WebRiskAudit",
  },
  description:
    "WebRiskAudit is an open-source passive security scanner. It checks a domain's email authentication, TLS certificate, HTTP security headers and a few other public signals. Results are automated and heuristic.",
  keywords: [
    "WebRiskAudit",
    "passive security scanner",
    "security posture",
    "open source",
    "SPF",
    "DKIM",
    "DMARC",
    "TLS certificate",
    "HTTP security headers",
  ],
  authors: [{ name: "Taha Gökalp Bakar", url: "https://github.com/portakalp" }],
  creator: "Taha Gökalp Bakar",
  formatDetection: {
    email: false,
    address: false,
    telephone: false,
  },
  openGraph: {
    title: "WebRiskAudit | Open-source passive security scanner",
    description:
      "A passive security posture check for a domain: email authentication, TLS certificate, HTTP security headers and a few other public signals.",
    url: "https://webriskaudit.com",
    siteName: "WebRiskAudit",
    locale: "en_US",
    type: "website",
    images: [
      {
        url: "/icon.png",
        width: 512,
        height: 512,
        alt: "WebRiskAudit logo",
      },
    ],
  },
  twitter: {
    card: "summary",
    title: "WebRiskAudit | Open-source passive security scanner",
    description:
      "A passive security posture check for a domain. Automated, heuristic results from DNS lookups, one TLS handshake and a few HTTP requests.",
    images: ["/icon.png"],
  },
  alternates: {
    canonical: "/",
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-video-preview": -1,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
  icons: {
    icon: [
      {
        url: "/icon.png",
        type: "image/png",
        sizes: "512x512",
      },
    ],
    apple: [
      {
        url: "/icon.png",
      },
    ],
  },
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "WebApplication",
    name: "WebRiskAudit",
    url: "https://webriskaudit.com",
    description:
      "Open-source passive security scanner that checks a domain's email authentication, TLS certificate, HTTP security headers and a few other public signals.",
    applicationCategory: "SecurityApplication",
    isAccessibleForFree: true,
    author: {
      "@type": "Person",
      name: "Taha Gökalp Bakar",
      url: "https://github.com/portakalp",
    },
    sameAs: "https://github.com/portakalp/webriskaudit",
  }

  return (
    <html lang="en">
      <body className={`font-sans antialiased`}>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
        {children}
      </body>
    </html>
  )
}
