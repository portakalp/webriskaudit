import type React from "react"
import type { Metadata } from "next"
import Script from "next/script"
import { Plus_Jakarta_Sans, JetBrains_Mono } from "next/font/google"
import { Analytics } from "@vercel/analytics/next"
import { CookieBanner } from "@/components/cookie-banner"
import "./globals.css"

const _plusJakartaSans = Plus_Jakarta_Sans({ subsets: ["latin"] })
const _jetbrainsMono = JetBrains_Mono({ subsets: ["latin"] })

export const metadata: Metadata = {
  metadataBase: new URL("https://webriskaudit.com"),
  title: {
    default: "Web Risk Audit | Digital Asset Security Audits (Cyber Shield, Full Armor, Digital Bodyguard)",
    template: "%s | Web Risk Audit",
  },
  description:
    "Expert Web Risk Audit services for European SMEs. We provide evidence-based digital asset security audits, severity ratings, and prioritized remediation backlogs. No implementation included.",
  keywords: [
    "Web Risk Audit",
    "Digital Asset Security",
    "Cyber Shield",
    "Full Armor",
    "Digital Bodyguard",
    "SME Security Audit",
    "Vulnerability Assessment",
  ],
  authors: [{ name: "Web Risk Audit Agency" }],
  creator: "Web Risk Audit Agency",
  publisher: "Web Risk Audit Agency",
  formatDetection: {
    email: false,
    address: false,
    telephone: false,
  },
  openGraph: {
    title: "Web Risk Audit | Digital Asset Security Audits",
    description:
      "Secure your business with expert digital asset security audits. We deliver evidence, severity ratings, and a prioritized remediation backlog for your team to implement.",
    url: "https://webriskaudit.com",
    siteName: "Web Risk Audit Agency",
    locale: "en_US",
    type: "website",
    images: [
      {
        url: "/images/hero-vector-v2.png", // Using the hero image as OG image
        width: 800,
        height: 700,
        alt: "Web Risk Audit Security Shield",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "Web Risk Audit | Digital Asset Security Audits",
    description:
      "Expert digital asset security audits. Evidence, severity ratings, and prioritized remediation backlogs.",
    images: ["/images/hero-vector-v2.png"],
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
        url: "/kaleicon.png?v=2",
        type: "image/png",
        sizes: "512x512",
      },
    ],
    apple: [
      {
        url: "/kaleicon.png?v=2",
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
    "@type": "ProfessionalService",
    name: "Web Risk Audit Agency",
    image: "https://webriskaudit.com/icon.png",
    description:
      "Provider of expert digital asset security audits, vulnerability assessments, and prioritized remediation plans for SMEs.",
    url: "https://webriskaudit.com",
    telephone: "", // User didn't provide a phone number in the prompt
    address: {
      "@type": "PostalAddress",
      addressCountry: "PL", // Poland as requested
    },
    priceRange: "€0 - €3900",
    serviceType: ["Cybersecurity Audit", "Vulnerability Assessment", "Compliance Audit"],
    offers: {
      "@type": "Offer",
      price: "0",
      priceCurrency: "EUR",
      name: "Free Audit & Diagnostics",
    },
    sameAs: [],
  }

  return (
    <html lang="en">
      <head>
        <Script
          src="https://www.googletagmanager.com/gtag/js?id=G-HS3PQE5Z4S"
          strategy="afterInteractive"
        />
        <Script id="google-analytics" strategy="afterInteractive">
          {`
            window.dataLayer = window.dataLayer || [];
            function gtag(){dataLayer.push(arguments);}
            gtag('js', new Date());
            gtag('config', 'G-HS3PQE5Z4S');
          `}
        </Script>
      </head>
      <body className={`font-sans antialiased`}>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
        {children}
        <Analytics />
        <CookieBanner />
      </body>
    </html>
  )
}
