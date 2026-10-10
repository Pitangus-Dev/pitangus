import { useId } from 'react'
import { useTranslation } from 'react-i18next'
import { ExternalLink } from 'lucide-react'
import type { GuidanceLink } from '@/features/findings/finding-model'

// The OWASP pages about a finding (cheat sheets, Top 10 category, API Top 10, WSTG), after the tool's own references.
// Titles and URLs come from Pitangus's curated mapping, never from the scan; only https links are shown.
export function OwaspGuidance({ links }: { links?: GuidanceLink[] | null }) {
  const { t } = useTranslation('findings')
  const heading = useId()
  const safe = (links ?? []).filter(link => /^https:\/\//i.test(link.url))
  if (!safe.length) return null
  return <section aria-labelledby={heading} className="mt-3">
    <h3 id={heading} className="mb-1 text-xs font-medium text-app-muted">{t('guidance.title')}<span className="font-normal text-app-subtle"> · {t('guidance.hint')}</span></h3>
    <ul className="space-y-1 text-xs">{safe.map(link => <li key={link.url} className="min-w-0">
      <a href={link.url} title={link.url} target="_blank" rel="noreferrer" className="inline-flex min-h-6 max-w-full items-center gap-1 text-brand hover:underline">
        <span className="truncate">{link.title}</span><ExternalLink aria-hidden className="size-3 shrink-0" /><span className="sr-only">{t('guidance.new_tab')}</span>
      </a>
    </li>)}</ul>
  </section>
}
