import type { ReactNode } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { ArrowSquareOutIcon } from '@phosphor-icons/react'
import { Badge } from '@/shared/ui/badge'
import { formatCalendarDay, formatDate, formatNumber } from '@/shared/i18n/format'
import { slaText } from '@/features/findings/sla'
import { AiPrompt } from '@/features/findings/ai-prompt'
import { FixSection, Reverify } from '@/features/findings/fix-guide'
import { WebFinding } from '@/features/findings/web-finding'
import { OwaspGuidance } from '@/features/findings/guidance'
import { TriageActions, TriageHistory } from '@/features/findings/triage'
import { TRIAGE_LABEL, type TriageStatus } from '@/features/findings/triage-status'
import { SEVERITY_LABEL, idOf, labelOf, locationOf, severityClass, statusOf, toolName, type Lifecycle, type RepositoryFinding } from '@/features/findings/finding-model'

// One finding, expanded: what it is, how to fix and verify it, its triage and how it got here. `runId`: the run or asset
// state to re-verify it against; `jira`: its Jira action; `heading`: what names it inside its group (a web problem's URL)
// when the group's row already says what it is.
export function FindingDetail({ finding, runId, demo, canAccept, onPick, onChanged, jira, heading }: { finding: RepositoryFinding; runId: string; demo: boolean; canAccept: boolean; onPick: (status: TriageStatus) => void; onChanged: () => void; jira: ReactNode; heading?: string }) {
  const { t } = useTranslation('findings')
  const advisory = finding.advisory
  const pkg = finding.package
  const web = finding.scanner === 'dast'
  return <div id={`finding-${idOf(finding)}`} tabIndex={-1} className="rounded-xl border border-app-line bg-panel p-4">
    <div className="flex flex-wrap items-start justify-between gap-2"><div className="min-w-0">{heading ? <p className="font-mono text-sm font-medium break-all">{heading}</p> : <p className="text-sm font-medium">{advisory?.summary || finding.title}</p>}<p className="mt-1 flex flex-wrap gap-x-2 font-mono text-xs text-app-subtle"><span className="text-app-secondary">{finding.rule_id}</span>{finding.cve.filter(id => id !== finding.rule_id).map(id => <a key={id} href={`https://www.cve.org/CVERecord?id=${id}`} target="_blank" rel="noreferrer" className="text-brand underline underline-offset-2">{id}</a>)}{finding.ghsa.filter(id => id !== finding.rule_id).map(id => <a key={id} href={`https://github.com/advisories/${id}`} target="_blank" rel="noreferrer" className="text-brand underline underline-offset-2">{id}</a>)}{finding.cwe.map(id => <a key={id} href={`https://cwe.mitre.org/data/definitions/${id}.html`} target="_blank" rel="noreferrer" className="hover:underline">CWE-{id}</a>)}</p></div><Badge variant="outline" className={severityClass(finding.severity)}>{labelOf(t, SEVERITY_LABEL, finding.severity)}{advisory?.cvss_score !== null && advisory?.cvss_score !== undefined ? ` · ${advisory.cvss_score}` : ''}</Badge></div>
    <div className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
      {pkg?.dev && <Fact label={t('detail.type')}><span className="rounded border border-app-line px-1.5 py-0.5 text-xs">{t('detail.dev_dependency')}</span> <span className="text-xs text-app-subtle">{t('detail.dev_hint')}</span></Fact>}
      {pkg && <Fact label={t('detail.fix')}>{pkg.fixed_version ? <><span className="font-mono">{pkg.version}</span> → <span className="font-mono font-medium text-success">{pkg.fixed_version}</span></> : t('detail.no_fix')}</Fact>}
      {!pkg && !web && <Fact label={t('detail.location')}><span className="font-mono text-xs">{locationOf(finding)}</span></Fact>}
      {finding.framework && <Fact label={t('detail.technology')}>{finding.framework}</Fact>}
      {finding.epss && <Fact label={t('detail.epss')}>{formatNumber(finding.epss.score, { style: 'percent', minimumFractionDigits: 2, maximumFractionDigits: 2 })} <span className="text-app-subtle">{t('detail.percentile', { value: formatNumber(Math.round(finding.epss.percentile * 100)) })}</span></Fact>}
      {finding.kev && <Fact label="CISA KEV">{t('detail.kev_since', { date: finding.kev.date_added ? formatCalendarDay(finding.kev.date_added) : '' })}{finding.kev.ransomware ? ` · ${t('detail.kev_ransomware')}` : ''}</Fact>}
      {advisory?.cvss_vector && <Fact label={t('detail.cvss_vector')}><span className="font-mono text-xs break-all">{advisory.cvss_vector}</span></Fact>}
    </div>
    {web ? <WebFinding finding={finding} /> : <FixSection fix={finding.fix} remediation={finding.remediation} />}
    {!demo && !web && finding.lifecycle?.status !== 'fixed' && <AiPrompt runId={runId} fingerprint={finding.fingerprint} />}
    {finding.lifecycle?.status !== 'excluded' && (finding.lifecycle?.status !== 'fixed' || finding.verification) && <Reverify runId={runId} fingerprint={finding.fingerprint} verification={finding.verification}
      onChanged={onChanged} canVerify={finding.lifecycle?.status !== 'fixed'} web={web}
      blocked={demo ? t('verify.demo')
        : finding.lifecycle?.origin?.kind === 'pr' && !finding.lifecycle.origin.merged ? t('verify.open_pr')
        : finding.lifecycle?.origin?.kind === 'import' ? t('verify.imported', { tool: finding.lifecycle.origin.tool || finding.tool || 'SARIF' }) : null} />}
    {finding.priority && <p className="mt-3 text-xs leading-5 text-app-subtle"><span className="font-medium text-app-muted">{t('detail.why_priority')} </span>{finding.priority.factors.join(' · ')}</p>}
    {(finding.tool || finding.also_detected_by?.length) && <p className="mt-2 text-xs text-app-subtle">{finding.also_detected_by?.length
      ? t('detail.detected_by_also', { tool: toolName(t, finding.tool ?? ''), others: finding.also_detected_by.map(tool => toolName(t, tool)).join(', ') })
      : t('detail.detected_by', { tool: toolName(t, finding.tool ?? '') })}{finding.related_rules?.length ? <> · <Trans t={t} i18nKey="detail.related" values={{ rules: finding.related_rules.join(', ') }} components={{ mono: <span className="font-mono" /> }} /></> : null}.</p>}
    {finding.source?.name && <p className="mt-1 text-xs text-app-subtle">{t('detail.advisory_source')} {finding.source.url
      ? <a href={finding.source.url} target="_blank" rel="noreferrer" className="underline decoration-app-faint underline-offset-2 hover:text-app-fg">{finding.source.name}</a>
      : finding.source.name} · {finding.source.license}{finding.source.terms === 'non-commercial' && <span className="text-attention"> · {t('detail.non_commercial')}</span>}</p>}
    {(finding.count ?? 1) > 1 && <details className="mt-2 text-xs text-app-subtle"><summary className="cursor-pointer text-app-muted">{t('detail.copies', { count: finding.count })}</summary>
      <ul className="mt-1 space-y-0.5">{(finding.instances ?? []).map(item => <li key={`${item.path}:${item.line ?? ''}`}><span className="font-mono break-all">{item.line ? `${item.path}:${item.line}` : item.path}</span>{item.unseen ? <span className="text-attention"> · {t('detail.copy_unverified')}</span> : null}</li>)}</ul>
      {(finding.instances?.length ?? 0) < (finding.count ?? 0) && <p className="mt-1">{t('detail.copies_more', { count: (finding.count ?? 0) - (finding.instances?.length ?? 0) })}</p>}</details>}
    <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-app-line bg-inset p-3">
      <div className="min-w-0 text-xs text-app-muted"><span className="font-medium text-app-secondary">{t('detail.triage', { status: finding.triage?.expired ? t('detail.triage_expired') : t(TRIAGE_LABEL[statusOf(finding)]) })}</span>{finding.triage?.by ? ` · ${finding.triage.by}` : ''}{finding.triage?.expires_at ? ` · ${t('triage.expires_on', { date: formatCalendarDay(finding.triage.expires_at) })}` : ''}{finding.triage?.reason ? <span className="mt-0.5 block">{finding.triage.reason}</span> : null}</div>
      <div className="flex flex-wrap items-center gap-2">{jira}<TriageActions current={statusOf(finding)} canAccept={canAccept} onPick={onPick} size="xs" /></div>
    </div>
    {finding.lifecycle && <p className="mt-2 text-xs leading-5 text-app-subtle"><span className="font-medium text-app-muted">{t('lifecycle.label')} </span>{finding.lifecycle.origin?.kind === 'pr'
      ? (finding.lifecycle.origin.branch
        ? t(finding.lifecycle.origin.merged ? 'lifecycle.from_pr_branch_merged' : 'lifecycle.from_pr_branch', { number: finding.lifecycle.origin.pr, branch: finding.lifecycle.origin.branch })
        : t(finding.lifecycle.origin.merged ? 'lifecycle.from_pr_merged' : 'lifecycle.from_pr', { number: finding.lifecycle.origin.pr }))
      : finding.lifecycle.origin?.kind === 'import' ? t('lifecycle.from_import', { tool: finding.lifecycle.origin.tool || finding.tool || 'SARIF' })
      : t('lifecycle.main')}{finding.lifecycle.first_seen ? ` · ${t('lifecycle.first_seen', { date: formatDate(finding.lifecycle.first_seen) })}` : ''}{finding.lifecycle.last_seen ? ` · ${t('lifecycle.last_seen', { date: formatDate(finding.lifecycle.last_seen) })}` : ''}{finding.lifecycle.reopened_at ? ` · ${t('lifecycle.reopened')}` : ''}{finding.lifecycle.unseen ? <span className="block text-attention"><Unseen unseen={finding.lifecycle.unseen} /></span> : null}{finding.sla ? <span className={`block ${finding.sla.state === 'overdue' ? 'text-danger' : finding.sla.state === 'soon' ? 'text-attention' : ''}`}>{t('lifecycle.sla', { count: finding.sla.days, due: finding.sla.due, status: slaText(finding.sla).toLowerCase() })}</span> : null}{finding.lifecycle.fixed ? <span className="block text-success">{t('lifecycle.auto_fixed', { how: finding.lifecycle.fixed.how })}</span> : null}{finding.lifecycle.status === 'excluded' ? <span className="block">{finding.lifecycle.excluded?.reason ?? (finding.lifecycle.excluded?.pattern
      ? <Trans t={t} i18nKey="lifecycle.excluded_pattern" values={{ pattern: finding.lifecycle.excluded.pattern }} components={{ code: <code className="font-mono" /> }} />
      : t('lifecycle.excluded'))}</span> : null}</p>}
    <TriageHistory state={finding.triage} />
    {advisory?.details && <details className="mt-3"><summary className="cursor-pointer text-xs text-app-muted">{t('detail.advisory_details')}</summary><p className="mt-2 text-xs leading-5 whitespace-pre-line text-app-muted">{advisory.details}</p></details>}
    {advisory?.references.length ? <p className="mt-3 flex flex-wrap gap-x-3 text-xs">{advisory.references.slice(0, 4).map(url => <a key={url} href={url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-brand underline underline-offset-2">{new URL(url).hostname} <ArrowSquareOutIcon className="size-3" /></a>)}</p> : null}
    <OwaspGuidance links={finding.guidance} />
  </div>
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return <div><span className="block text-xs text-app-subtle">{label}</span><span className="text-app-secondary">{children}</span></div>
}

const UNSEEN_CAUSE = { rule_off: 'lifecycle.unseen_rule_off', engine_off: 'lifecycle.unseen_engine_off', rule_changed: 'lifecycle.unseen_rule_changed' } as const

// Why a finding is unverified: a change of configuration names what changed and which rule or engine; a secret whose
// value couldn't be read, that its file still has one like it; anything else is a scan that couldn't look.
function Unseen({ unseen }: { unseen: NonNullable<Lifecycle['unseen']> }) {
  const { t } = useTranslation('findings')
  const date = formatDate(unseen.since)
  const named = unseen.cause === 'engine_off' ? Boolean(unseen.engine) : Boolean(unseen.rule)
  if (unseen.reason === 'configuration' && unseen.cause && unseen.cause in UNSEEN_CAUSE && named)
    return <Trans t={t} i18nKey={UNSEEN_CAUSE[unseen.cause]} values={{ date, rule: unseen.rule ?? '', engine: toolName(t, unseen.engine ?? '') }}
      components={{ code: <code className="font-mono" translate="no" /> }} />
  if (unseen.reason === 'configuration') return <>{t('lifecycle.unseen_configuration', { date })}</>
  if (unseen.reason === 'unidentified') return <>{t('lifecycle.unseen_unidentified', { date })}</>
  return <>{t('lifecycle.unseen', { date, count: unseen.scans })}</>
}
