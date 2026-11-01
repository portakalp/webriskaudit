import Link from "next/link"

export function SiteFooter() {
  return (
    <footer className="relative z-20 w-full px-6 py-6">
      <div className="max-w-4xl mx-auto text-center space-y-3">
        <nav className="flex flex-wrap justify-center gap-x-6 gap-y-2 text-sm text-slate-600">
          <a
            href="https://github.com/portakalp/webriskaudit"
            className="hover:text-slate-900 transition-colors underline"
          >
            Open source on GitHub
          </a>
          <span>
            Built by{" "}
            <a
              href="https://github.com/portakalp"
              className="hover:text-slate-900 transition-colors underline"
            >
              Taha Gökalp Bakar
            </a>
          </span>
          <Link
            href="/privacy-policy"
            className="hover:text-slate-900 transition-colors underline"
          >
            Privacy
          </Link>
        </nav>
        <p className="text-xs text-slate-500">
          Automated, heuristic results from passive checks. Not a substitute for a professional security assessment.
        </p>
      </div>
    </footer>
  )
}
