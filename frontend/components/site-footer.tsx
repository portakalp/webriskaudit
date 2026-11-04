import Link from "next/link"

const LINK = "rounded underline underline-offset-2 transition-colors hover:text-slate-900"

export function SiteFooter() {
  return (
    <footer className="relative z-20 w-full px-6 py-6">
      <div className="mx-auto max-w-4xl space-y-3 text-center">
        <nav aria-label="Footer" className="flex flex-wrap justify-center gap-x-6 gap-y-2 text-sm text-slate-700">
          <a href="https://github.com/portakalp/webriskaudit" className={LINK}>
            Open source on GitHub
          </a>
          <span>
            Built by{" "}
            <a href="https://github.com/portakalp" className={LINK}>
              Taha Gökalp Bakar
            </a>
          </span>
          <Link href="/privacy-policy" className={LINK}>
            Privacy
          </Link>
        </nav>
        <p className="text-pretty text-xs text-slate-600">
          Passive checks only: DNS lookups, TLS handshakes and HTTP GET requests for the home page. Automated,
          heuristic results; not a substitute for a professional security assessment.
        </p>
      </div>
    </footer>
  )
}
