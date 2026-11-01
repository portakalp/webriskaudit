import type { Metadata } from "next"

// A page's openGraph or twitter object replaces the layout's instead of
// merging with it, so pages that set their own spread these in.
export const openGraphDefaults = {
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
} satisfies Metadata["openGraph"]

export const twitterDefaults = {
  card: "summary",
  images: ["/icon.png"],
} satisfies Metadata["twitter"]
