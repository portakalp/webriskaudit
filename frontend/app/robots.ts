import { MetadataRoute } from 'next'

export const dynamic = "force-static"

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: '*',
      allow: ['/', '/llms.txt'],
      disallow: '',
    },
    sitemap: 'https://webriskaudit.com/sitemap.xml',
  }
}
