import { useId, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { ExternalLink } from 'lucide-react'
import { CodeBlock } from '@/features/findings/fix-guide'
import { toolName, type RepositoryFinding } from '@/features/findings/finding-model'

// A web finding, top to bottom: what it is, where, the evidence, how to fix it, how to check it and references. The
// scanner's own text is shown as published and attributed; Pitangus only adds what it derives (highlight, curl check).
export function WebFinding({ finding }: { finding: RepositoryFinding }) {
  const { t } = useTranslation('findings')
  const web = finding.web ?? {}
  const tool = toolName(t, finding.tool ?? '')
  const said = tool ? t('web.according_to', { tool }) : undefined
  const highlight = finding.fix?.web?.highlight
  const check = finding.fix?.web?.check
  const checkLabel = finding.fix?.commands?.[0]?.label ?? t('web.how_to_check')
  const [more, setMore] = useState(false)
  const references = (web.references ?? []).filter(url => /^https?:\/\//i.test(url))
  // Old findings kept only the message and the solution inside our own sentence ("ZAP reports: …"): shown as they are.
  const showReason = !!finding.reason && !(web.description && finding.reason.includes(web.description))
  return <div className="mt-3 space-y-3">
    <Section title={t('web.what')} note={web.description ? said : undefined}>
      {showReason && <p className="whitespace-pre-line wrap-anywhere">{finding.reason}</p>}
      {web.description && <>
        <p className={`whitespace-pre-line wrap-anywhere ${showReason ? 'mt-1 text-xs text-app-muted' : ''} ${more ? '' : 'line-clamp-3'}`}>{web.description}</p>
        {web.description.length > 240 && <button type="button" aria-expanded={more} onClick={() => setMore(value => !value)} className="mt-1 min-h-6 text-xs text-brand underline underline-offset-2">{more ? t('web.show_less') : t('web.show_more')}</button>}
      </>}
    </Section>
    <Section title={t('web.where')}>
      <p className="font-mono text-xs break-all">{web.method && <span className="mr-1.5 rounded border border-app-line px-1 py-0.5 text-app-muted">{web.method}</span>}{finding.path}</p>
      {web.parameter && <p className="mt-1 text-xs text-app-muted">{t('web.parameter')} <code className="rounded border border-app-line bg-inset px-1 py-0.5 font-mono text-app-secondary">{web.parameter}</code></p>}
    </Section>
    {(web.evidence || web.attack) && <Section title={t('web.evidence')}>
      {web.evidence && <pre className="rounded-lg border border-app-line bg-inset p-3 font-mono text-xs leading-5 whitespace-pre-wrap text-app-secondary wrap-anywhere">{highlight
        ? <>{highlight.before}<mark className="rounded-sm bg-attention-soft px-0.5 font-semibold text-attention">{highlight.match}</mark>{highlight.after}</>
        : web.evidence}</pre>}
      {web.evidence && highlight && <p className="mt-1 text-xs text-app-subtle">{t('web.highlighted')}</p>}
      {web.attack && web.attack !== web.evidence && <div className="mt-2"><p className="text-xs text-app-muted">{t('web.attack')}</p>
        <pre className="mt-1 rounded-lg border border-app-line bg-inset p-3 font-mono text-xs leading-5 whitespace-pre-wrap text-app-secondary wrap-anywhere">{web.attack}</pre></div>}
    </Section>}
    {web.also?.length ? <Section title={t('web.also_reported')}>
      <ul className="space-y-2 text-xs">{web.also.map(item => <li key={`${item.tool}:${item.rule_id}`} className="min-w-0">
        <p><span className="font-medium text-app-fg">{toolName(t, item.tool)}</span>{item.title ? ` · ${item.title}` : ''} · <code className="font-mono text-app-muted">{item.rule_id}</code></p>
        {item.evidence && <pre className="mt-1 rounded-lg border border-app-line bg-inset p-2 font-mono text-xs leading-5 whitespace-pre-wrap text-app-secondary wrap-anywhere">{item.evidence}</pre>}
      </li>)}</ul>
    </Section> : null}
    <Section title={t('web.how_to_fix')} note={web.solution ? said : undefined} tone="brand">
      <p className="whitespace-pre-line wrap-anywhere">{web.solution || finding.remediation}</p>
    </Section>
    {check && <Section title={t('web.how_to_check')}>
      <CodeBlock code={check} label={checkLabel} /><p className="mt-1 text-xs text-app-muted">{t('web.check_hint')}</p>
    </Section>}
    {references.length > 0 && <Section title={t('web.references')} note={said}>
      <ul className="space-y-1 text-xs">{references.map(url => <li key={url} className="min-w-0"><a href={url} title={url} target="_blank" rel="noreferrer" className="inline-flex min-h-6 max-w-full items-center gap-1 text-brand underline underline-offset-2"><span className="truncate">{label(url)}</span><ExternalLink className="size-3 shrink-0" /><span className="sr-only">{t('web.new_tab')}</span></a></li>)}</ul>
    </Section>}
  </div>
}

function label(url: string) {
  try { const parsed = new URL(url); return parsed.hostname + (parsed.pathname === '/' ? '' : parsed.pathname) } catch { return url }
}

function Section({ title, note, tone, children }: { title: string; note?: string; tone?: 'brand'; children: ReactNode }) {
  const heading = useId()
  return <section aria-labelledby={heading} className={tone === 'brand' ? 'rounded-lg border border-app-line bg-inset p-3' : ''}>
    <h3 id={heading} className={`mb-1 text-xs font-medium ${tone === 'brand' ? 'text-app-fg' : 'text-app-muted'}`}>{title}{note && <span className="font-normal text-app-subtle"> · {note}</span>}</h3>
    <div className="text-sm text-app-secondary">{children}</div>
  </section>
}
