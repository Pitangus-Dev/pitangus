import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Trans, useTranslation } from 'react-i18next'
import { apiPost } from '@/shared/api/client'
import { api } from '@/shared/api/http'
import { domainScopeQuery, domainsQuery, keys, registriesQuery, repositoryPlanQuery, sourceCountQuery, sourceQuery, type QueuedDomainScan } from '@/shared/api/queries'
import { formatList } from '@/shared/i18n/format'
import type { Source } from '@/features/sources/sources'
import { ScheduleOption, type SchedulePlan } from '@/features/analyses/wizard/schedule-option'
import { defaultRule, normalized, ruleOf, sameRule } from '@/features/domains/schedule'
import { accessOf, sameAccess, usableAccess } from '@/features/domains/schedule-access-model'
import { SarifImport } from '@/features/analyses/sarif-import'
import { useBatches } from '@/features/analyses/use-batches'
import { AccessStep } from '@/features/analyses/wizard/access-step'
import { ContextStep } from '@/features/analyses/wizard/context-step'
import { ImagesStep } from '@/features/analyses/wizard/images-step'
import { RepositoriesStep, type CodeTarget } from '@/features/analyses/wizard/repositories-step'
import { DetailList, LooksFor, OsvOption, ReviewStep, type ReviewRow } from '@/features/analyses/wizard/review-step'
import { EgressNote } from '@/features/analyses/wizard/egress-note'
import { StepRail } from '@/features/analyses/wizard/step-frame'
import { TargetStep, type WebTarget } from '@/features/analyses/wizard/target-step'
import { TypeChooser } from '@/features/analyses/wizard/type-chooser'
import { STEPS, USERS_PER_SCAN, duration, inScope, listing, referencesOf, registryOf, signInHost, type Kind, type ScanPlan, type Spec } from '@/features/analyses/wizard/model'

type Start = Kind | 'import' | null
const KIND_TITLE = { code: 'wizard.kinds.code.title', image: 'wizard.kinds.image.title', web: 'wizard.kinds.web.title' } as const
const CHOOSER = -1

// New scan: choose what to check, answer one question per step, review and launch. Several repositories (or an
// organization, or several images) become a batch that moves forward when the server is free; a web scan takes one
// verified domain, and an API spec when there is one. A direct link brings a repository or a domain already chosen.
export function AnalysisWizard({ onComplete, onBatchStarted, onScheduled, onManageConnections, onCancel, initialSourceId, initialDomainId = null, initialKind = null, isAdmin }: {
  onComplete: (id: string) => Promise<void>; onBatchStarted: () => void; onScheduled?: (domainId: string) => void; onManageConnections: () => void; onCancel: () => void
  initialSourceId: string | null; initialDomainId?: string | null; initialKind?: Start; isAdmin: boolean
}) {
  const { t } = useTranslation('analyses')
  const queryClient = useQueryClient()
  const start: Start = initialSourceId ? 'code' : initialKind
  const [kind, setKind] = useState<Start>(start)
  const [choice, setChoice] = useState<Kind>(start && start !== 'import' ? start : 'code')
  const [step, setStep] = useState(0)
  const [code, setCode] = useState<CodeTarget>({ mode: 'repos', sources: [], organization: '' })
  const [imageText, setImageText] = useState('')
  const [context, setContext] = useState('')
  const [target, setTarget] = useState<WebTarget>({ domain: null, scopeOpen: false })
  const [spec, setSpec] = useState<Spec | null>(null)
  const [useHeaders, setUseHeaders] = useState(true)
  const [testUsers, setTestUsers] = useState<string[]>([])
  const [allowOsv, setAllowOsv] = useState(false)
  const [schedulePlan, setSchedulePlan] = useState<SchedulePlan | null>(null)

  const domains = useQuery(domainsQuery())
  const registries = useQuery(registriesQuery()).data?.registries
  const { active: activeBatch } = useBatches()
  const linked = useQuery({ ...sourceQuery<Source>(initialSourceId ?? ''), enabled: !!initialSourceId })
  const [seededSource, setSeededSource] = useState(false)
  if (!seededSource && linked.data) { setSeededSource(true); setCode({ ...code, sources: [linked.data] }) }
  // From a domain's page: that domain already chosen, on the first step so its scope and API spec stay in view.
  const [seededDomain, setSeededDomain] = useState(!initialDomainId)
  if (!seededDomain && domains.data) {
    setSeededDomain(true)
    const found = domains.data.items.find(item => item.id === initialDomainId)
    if (found?.verified) setTarget({ domain: found, scopeOpen: false })
  }

  const steps = kind && kind !== 'import' ? STEPS[kind] : []
  const current = steps[step]
  const domain = target.domain ? domains.data?.items.find(item => item.id === target.domain?.id) ?? target.domain : null
  const references = referencesOf(imageText)
  const orgTotal = useQuery({ ...sourceCountQuery(code.organization), enabled: kind === 'code' && code.mode === 'org' && !!code.organization }).data ?? null
  const single = kind === 'code' && code.mode === 'repos' && code.sources.length === 1 ? code.sources[0].id : null
  const plan = useQuery({ ...repositoryPlanQuery<ScanPlan>(single ?? ''), enabled: !!single })
  const batch = kind === 'code' ? code.mode === 'org' || code.sources.length > 1 : kind === 'image' && references.length > 1
  // With the switch on, the scan reaches the hosts saved in the domain's scope (the server reads them again when it starts).
  const scopeOpen = kind === 'web' && !!domain && target.scopeOpen
  // Scheduled scans always use the saved scope, so it's read for the schedule's test users too.
  const savedScope = useQuery({ ...domainScopeQuery(domain?.id ?? ''), enabled: kind === 'web' && !!domain && domain.kind !== 'surface' }).data
  const scheduledHosts = savedScope?.covered ? savedScope.hosts.filter(item => item.state === 'in_scope').map(item => item.host) : []
  const hosts = scopeOpen ? scheduledHosts : []
  const headerNames = (domain?.headers ?? []).map(item => item.name)
  const sending = useHeaders && headerNames.length > 0
  // Only users still saved, signing in on a host this scope reaches (the scope can change after they were picked).
  const signingIn = (domain?.test_users ?? []).filter(user => testUsers.includes(user.id) && !signInHost(user, domain?.host ?? '', hosts)).slice(0, USERS_PER_SCAN)
  const specInvalid = spec?.mode === 'url' && !!domain && !inScope(spec.url, domain.host, hosts)
  // Until touched, the plan is the domain's own schedule (or none, with a default rule ready to switch on).
  // A new schedule signs in and sends headers like this scan does; an existing one keeps its own choice.
  const schedule: SchedulePlan = schedulePlan ?? { on: !!domain?.schedule, rule: domain?.schedule ? ruleOf(domain.schedule) : defaultRule(), alsoNow: true,
    access: domain?.schedule ? accessOf(domain.schedule) : { test_users: signingIn.map(user => user.id), use_headers: sending } }
  const scanNow = !schedule.on || schedule.alsoNow
  const osv = !!plan.data?.osv_needed && allowOsv

  const restart = () => { setKind(null); setStep(0) }
  const jump = (index: number) => index === CHOOSER ? restart() : setStep(index)
  const back = () => step === 0 ? restart() : setStep(step - 1)
  const next = () => setStep(step + 1)

  const launch = useMutation({
    mutationFn: async (): Promise<string | null> => {
      if (kind === 'web' && domain) {
        const access = usableAccess(domain, schedule.access, scheduledHosts)
        const changed = schedule.on ? !domain.schedule || !sameRule(ruleOf(domain.schedule), schedule.rule) || !sameAccess(accessOf(domain.schedule), access) : !!domain.schedule
        const saveSchedule = () => apiPost('/api/domains/schedule', 'schedule-domain', { domain_id: domain.id, schedule: schedule.on ? { ...normalized(schedule.rule), ...access } : null })
        if (!scanNow) {
          await saveSchedule()
          await queryClient.invalidateQueries({ queryKey: keys.domains })
          onScheduled?.(domain.id)
          return null
        }
        // With a spec the server calls its documented endpoints (API mode) instead of crawling the site.
        const source = spec ? spec.mode === 'file' ? { spec: { filename: spec.filename, content_base64: spec.content } } : { spec_url: spec.url } : {}
        const queued = await api.post<QueuedDomainScan>('/api/domains/scans', 'scan-domain', { domain_id: domain.id, mode: spec ? 'api' : 'web', ...(scopeOpen ? { use_scope: true } : {}), use_headers: sending,
          ...(signingIn.length ? { test_users: signingIn.map(user => user.id) } : {}), ...source })
        // Saved after the scan, so its next run skips today. The scan is queued either way; a schedule that didn't save
        // shows on the domain's page, not as a failed launch.
        if (changed) await saveSchedule().catch(() => null)
        void queryClient.invalidateQueries({ queryKey: keys.domains })
        return queued.run_id
      }
      if (batch) {
        if (kind === 'image') await api.post('/api/images/batches', 'scan-image-batch', { references, context })
        else if (code.mode === 'org') await api.post('/api/repositories/batches', 'scan-batch', { account: code.organization, context })
        else await api.post('/api/repositories/batches', 'scan-batch', { source_ids: code.sources.map(item => item.id), context })
        return null
      }
      const data = kind === 'image'
        ? await api.post<{ run: { id: string } }>('/api/images/scans', 'scan-image', { reference: references[0], context })
        : await api.post<{ run: { id: string } }>('/api/repositories/scans', 'scan-repository', { source_id: single, allow_osv_upload: osv, context })
      return data.run.id
    },
    onSuccess: async id => { if (id) await onComplete(id); else if (kind !== 'web') onBatchStarted() },
  })

  if (kind === 'import') return <SarifImport onOpenRun={onComplete} onBack={restart} />
  if (!kind) return <div className="max-w-6xl"><TypeChooser choice={choice} onChoose={setChoice} onContinue={() => { setKind(choice); setStep(0) }} onImport={() => setKind('import')}
    onCancel={onCancel} dast={domains.data?.dast} isAdmin={isAdmin} /></div>

  const typeRow = { label: t('review.type'), value: t(KIND_TITLE[kind]), step: CHOOSER }
  const contextIndex = steps.indexOf('context')
  const contextRow: ReviewRow = context.trim() ? { label: t('review.context'), value: context.trim(), step: contextIndex }
    : { label: t('review.context'), value: <Trans t={t} i18nKey="review.no_context" components={{ add: <button type="button" onClick={() => setStep(contextIndex)} className="min-h-6 font-medium text-brand underline underline-offset-2" /> }} /> }

  const review = () => {
    if (kind === 'code') {
      const names = listing(t, code.sources.map(item => item.name))
      const value = code.mode === 'org' ? orgTotal ? t('review.org_value', { name: code.organization, count: orgTotal, duration: duration(t, orgTotal * 60) }) : code.organization
        : code.sources.length > 1 ? t('review.target_repositories', { total: code.sources.length, names }) : names
      const rows = [typeRow, { label: t(code.mode === 'org' ? 'review.organization' : 'review.repositories'), value, step: 0 },
        { label: t('review.looks_for'), value: <LooksFor plan={plan.data} failed={plan.isError} batch={batch} osv={osv} /> }, contextRow]
      const label = code.mode === 'org' ? orgTotal ? t('launch.organization_count', { total: orgTotal }) : t('launch.organization')
        : code.sources.length > 1 ? t('launch.repositories', { total: code.sources.length }) : t('launch.code')
      return { rows, label,
        options: !batch && plan.data?.osv_needed ? <OsvOption checked={allowOsv} onChange={setAllowOsv} /> : undefined,
        notes: batch ? <p className="text-sm text-app-muted">{t('review.batch_note')}</p> : undefined,
        details: <>{plan.data && !batch && <>
          {plan.data.languages.length > 0 && <DetailList title={t('details.languages')} items={plan.data.languages.map(item => `${item.name} · ${item.rules ? t('details.rules', { count: item.rules }) : t('details.no_rules')}`)} />}
          <DetailList title={t('details.runs')} items={plan.data.runs} />
          {plan.data.skips.length > 0 && <DetailList title={t('details.skips')} items={plan.data.skips} />}</>}
          {(batch || !plan.data) && <p>{t('details.code_generic')}</p>}
          {batch && <p>{t('details.batch')}</p>}</> }
    }
    if (kind === 'image') {
      const registriesUsed = Array.from(new Set(references.map(registryOf).filter((item): item is string => !!item)))
      const access = registriesUsed.map(host => registries?.some(entry => entry.registry === host) ? t('review.registry_saved', { registry: host }) : t('review.registry_public', { registry: host }))
      const value = references.length > 1 ? t('review.target_images', { total: references.length, names: listing(t, references) }) : references[0]
      return { rows: [typeRow, { label: t('review.images'), value, step: 0 }, { label: t('review.registry'), value: access.join(' · '), step: 0 }, contextRow],
        label: references.length > 1 ? t('launch.images', { total: references.length }) : t('launch.image'),
        notes: batch ? <p className="text-sm text-app-muted">{t('review.batch_note')}</p> : undefined,
        details: <>
          <DetailList title={t('details.runs')} items={[t('details.image_runs.packages'), t('details.image_runs.secrets'), t('details.image_runs.config'), t('details.image_runs.checkov'), t('details.image_runs.priority')]} />
          <DetailList title={t('details.skips')} items={[t('details.image_skips.run'), t('details.image_skips.source'), t('details.image_skips.secrets')]} />
          {batch && <p>{t('details.batch')}</p>}</> }
    }
    const host = domain?.host ?? ''
    const access = [...(signingIn.length ? [t('review.access_users', { names: formatList(signingIn.map(user => user.name)) })] : []),
      ...(sending ? [t('review.access_value', { count: headerNames.length, names: formatList(headerNames) })] : [])]
    const specValue = spec ? spec.mode === 'file' ? `${spec.filename} · ${t('spec.summary', { version: spec.version, count: spec.endpoints })}` : spec.url : t('review.spec_none')
    const rows: ReviewRow[] = [typeRow,
      { label: t('review.target'), value: hosts.length ? t('review.scope_value', { host, count: hosts.length }) : host, step: 0 },
      ...(spec || domain?.kind === 'api' ? [{ label: t('review.spec'), value: specValue, step: 0 }] : []),
      { label: t('review.access'), value: access.length ? access.join(' · ') : t('review.access_none'), step: steps.indexOf('access') },
      ...(domain?.context ? [{ label: t('review.context'), value: domain.context }] : [])]
    return { rows, label: scanNow ? t('launch.web') : t('launch.schedule'),
      options: !domain || domain.kind === 'surface' ? undefined : <ScheduleOption value={schedule} onChange={setSchedulePlan} domain={domain} hosts={scheduledHosts} lastScanAt={domain?.last_scan?.created_at as string | undefined}
        hint={spec ? t('review.schedule_without_spec') : undefined} />,
      notes: <EgressNote egress={domains.data?.egress} admin={isAdmin} />, details: undefined }
  }

  const view = (() => {
    const frame = { onBack: back, onContinue: next }
    if (current === 'repositories') return <RepositoriesStep value={code} onChange={setCode} orgTotal={orgTotal} isAdmin={isAdmin} loading={!!initialSourceId && linked.isPending} batchBusy={!!activeBatch} onManageConnections={onManageConnections} {...frame} />
    if (current === 'images') return <ImagesStep text={imageText} onText={setImageText} registries={registries} batchBusy={!!activeBatch} onManageConnections={onManageConnections} {...frame} />
    if (current === 'context') return <ContextStep value={context} onChange={setContext} {...frame} />
    if (current === 'target') return <TargetStep value={target} spec={spec} onSpec={setSpec} specInvalid={specInvalid} {...frame}
      onChange={value => { if (value.domain?.id !== target.domain?.id) { setSpec(null); setUseHeaders(true); setTestUsers([]); setSchedulePlan(null) } setTarget(value) }} />
    if (current === 'access' && domain) return <AccessStep domain={domain} hosts={hosts} useHeaders={useHeaders} onUseHeaders={setUseHeaders}
      testUsers={testUsers} onTestUsers={setTestUsers} {...frame} />
    if (current === 'review') {
      const content = review()
      return <ReviewStep kind={kind} batch={batch} rows={content.rows} options={content.options} notes={content.notes} details={content.details}
        error={launch.error?.message ?? ''} busy={launch.isPending} launchLabel={content.label} onChange={jump} onBack={back} onLaunch={() => { if (!launch.isPending) launch.mutate() }} />
    }
    return null
  })()

  return <div className="grid max-w-6xl gap-8 xl:grid-cols-[minmax(0,1fr)_14rem]">
    <div className="min-w-0 space-y-8 xl:space-y-0">
      <div className="xl:hidden"><StepRail steps={steps} current={step} onJump={setStep} /></div>
      <div key={`${kind}-${current}`} className="min-w-0 space-y-4">
        {linked.isError && <p role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{linked.error.message}</p>}
        {view}
      </div>
    </div>
    <div className="hidden xl:block"><div className="sticky top-24"><StepRail steps={steps} current={step} onJump={setStep} vertical /></div></div>
  </div>
}
