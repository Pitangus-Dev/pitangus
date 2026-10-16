import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { CircleNotchIcon, DownloadSimpleIcon } from '@phosphor-icons/react'
import { apiPost, type Response } from '@/shared/api/client'
import { enginesQuery, keys } from '@/shared/api/queries'
import { formatDate } from '@/shared/i18n/format'
import { Button } from '@/shared/ui/button'
import { useConfirm } from '@/shared/ui/confirm'
import { Disclosure } from '@/shared/ui/disclosure'
import { SkeletonList } from '@/shared/ui/loading'
import { Notice } from '@/shared/ui/notice'
import { SettingsSection } from '@/shared/ui/settings-list'
import { Switch } from '@/shared/ui/switch'

type View = Response<'/api/engines'>
type Row = View['engines'][number]
type Group = Row['group']
type Capability = 'sast' | 'dependencies' | 'secrets' | 'iac' | 'pipelines' | 'images' | 'exposure'

const GROUPS: { id: Group; title: string; description: string }[] = [
  { id: 'code', title: 'groups.code.title', description: 'groups.code.description' },
  { id: 'secrets', title: 'groups.secrets.title', description: 'groups.secrets.description' },
  { id: 'infrastructure', title: 'groups.infrastructure.title', description: 'groups.infrastructure.description' },
  { id: 'images', title: 'groups.images.title', description: 'groups.images.description' },
  { id: 'web', title: 'groups.web.title', description: 'groups.web.description' },
]
// What each engine adds (its row) and what goes unchecked without it (the confirmation), as literal keys.
const ADDS: Record<string, string> = {
  opengrep: 'rows.opengrep.adds', trivy: 'rows.trivy.adds', 'osv-scanner': 'rows.osv_scanner.adds', betterleaks: 'rows.betterleaks.adds',
  checkov: 'rows.checkov.adds', zizmor: 'rows.zizmor.adds', grype: 'rows.grype.adds', httpx: 'rows.httpx.adds', testssl: 'rows.testssl.adds',
  nuclei: 'rows.nuclei.adds', dast: 'rows.dast.adds', katana: 'rows.katana.adds',
}
const COVERS: Record<string, string> = {
  opengrep: 'rows.opengrep.covers', trivy: 'rows.trivy.covers', 'osv-scanner': 'rows.osv_scanner.covers', betterleaks: 'rows.betterleaks.covers',
  checkov: 'rows.checkov.covers', zizmor: 'rows.zizmor.covers', grype: 'rows.grype.covers', httpx: 'rows.httpx.covers', testssl: 'rows.testssl.covers',
  nuclei: 'rows.nuclei.covers', dast: 'rows.dast.covers', katana: 'rows.katana.covers',
}
const CAPABILITY: Record<Capability, string> = {
  sast: 'capability.sast', dependencies: 'capability.dependencies', secrets: 'capability.secrets', iac: 'capability.iac',
  pipelines: 'capability.pipelines', images: 'capability.images', exposure: 'capability.exposure',
}
const IMAGE: Record<Row['image'], string> = {
  ready: 'image.ready', missing: 'image.missing', preparing: 'image.preparing', unknown: 'image.unknown', built_in: 'image.built_in',
}
const IMAGE_TONE: Record<Row['image'], string> = {
  ready: 'text-success', built_in: 'text-success', missing: 'text-attention', preparing: 'text-info', unknown: 'text-app-muted',
}
const isCapability = (value: string): value is Capability => value in CAPABILITY

// Which engines every scan runs. An admin turns each on or off from the next scan; one the server pins with its
// environment variable shows locked. Off never hides anything: the step says "not run (disabled)" and nothing it found
// is marked fixed. Each row also says whether the engine's images are on the worker's server, and prepares them.
export function EngineSwitches() {
  const { t } = useTranslation('engines')
  const queryClient = useQueryClient()
  const confirm = useConfirm()
  const query = useQuery(enginesQuery())
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const view = query.data

  const nameOf = (row: Row) => row.key === 'dast' ? t('rows.dast.title') : row.name
  // The kinds of check this engine would leave with no engine on.
  const leftBare = (row: Row) => row.covers.filter(isCapability).filter(capability => !view?.engines.some(other => other.key !== row.key && other.enabled && other.covers.includes(capability)))

  const run = async (key: string, call: () => Promise<View>, done: string) => {
    setBusy(key); setError(''); setNotice('')
    try {
      queryClient.setQueryData(keys.engines, await call())
      setNotice(done)
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy('') }
  }

  const toggle = async (row: Row, on: boolean) => {
    if (busy) return  // not disabled while busy: the switch keeps its focus through the confirmation
    const name = nameOf(row)
    if (on && row.key === 'dast'
      && !await confirm({ title: t('confirm.dast_title'), description: t('confirm.dast_body'), confirmLabel: t('confirm.on') })) return
    if (!on) {
      const bare = leftBare(row).map(capability => t(CAPABILITY[capability]))
      const description = <>
        <span className="block">{row.default ? t('confirm.off_core', { name, covers: t(COVERS[row.key] ?? '') }) : t('confirm.off_optional')}</span>
        {bare.map(what => <span key={what} className="mt-2 block">{t('confirm.off_last', { what })}</span>)}
      </>
      if (!await confirm({ title: t('confirm.off_title', { name }), description, confirmLabel: t('confirm.off') })) return
    }
    await run(row.key, () => apiPost('/api/engines', 'engine-switch', { engine: row.key, enabled: on }),
      on ? t('saved_on', { name }) : t('saved_off', { name }))
  }

  const prepare = (row: Row) => run(`${row.key}:prepare`, () => apiPost('/api/engines/prepare', 'prepare-engine', { engine: row.key }),
    t('preparing_notice', { name: nameOf(row) }))

  if (query.isPending) return <SkeletonList rows={6} label={t('loading')} />
  if (query.isError || !view) return <p role="alert" className="flex flex-wrap items-center gap-2 text-sm text-danger">{t('load_failed')}
    <Button size="xs" variant="outline" onClick={() => void query.refetch()}>{t('common:actions.retry')}</Button></p>

  const uncovered = view.uncovered.filter(isCapability)
  return <div className="space-y-8">
    <div className="space-y-3">
      <p className="max-w-3xl text-sm text-app-muted">{t('consequence')}</p>
      {uncovered.map(capability => <Notice key={capability} tone="attention" role="status">{t('uncovered', { what: t(CAPABILITY[capability]) })}</Notice>)}
      {error && <Notice tone="critical" blocking role="alert">{error}</Notice>}
      <p role="status" className="text-sm text-success empty:hidden">{notice}</p>
    </div>
    {GROUPS.map(group => <SettingsSection key={group.id} id={`engines-${group.id}`} title={t(group.title)} description={t(group.description)}>
      <ul className="divide-y divide-app-line border-y border-app-line">
        {view.engines.filter(row => row.group === group.id).map(row => <EngineRow key={row.key} row={row} name={nameOf(row)} adds={t(ADDS[row.key] ?? '')}
          busy={busy} requiresOff={!!row.requires && !view.engines.find(other => other.key === row.requires)?.enabled}
          onToggle={on => void toggle(row, on)} onPrepare={() => void prepare(row)} />)}
      </ul>
    </SettingsSection>)}
    <Disclosure summary={t('history.title')}>
      {view.history.length === 0 ? <p className="text-xs text-app-muted">{t('history.empty')}</p>
        : <ul className="space-y-1 text-xs text-app-muted">{view.history.map(entry => {
          const row = view.engines.find(item => item.key === entry.engine)
          const values = { by: entry.by ?? '—', name: row ? nameOf(row) : entry.engine, date: entry.at ? formatDate(entry.at) : '—' }
          return <li key={`${entry.at}-${entry.engine}`}>{entry.enabled ? t('history.on', values) : t('history.off', values)}</li>
        })}</ul>}
    </Disclosure>
  </div>
}

function EngineRow({ row, name, adds, busy, requiresOff, onToggle, onPrepare }: {
  row: Row; name: string; adds: string; busy: string; requiresOff: boolean; onToggle: (on: boolean) => void; onPrepare: () => void
}) {
  const { t } = useTranslation('engines')
  const origin = row.locked ? t('status.locked', { setting: row.setting })
    : row.source === 'workspace' && row.changed_at ? t('status.changed', { by: row.changed_by ?? '—', date: formatDate(row.changed_at) })
    : row.enabled ? t('status.default_on') : t('status.default_off')
  const hint = <>
    <span className="block">{adds}</span>
    <span className="block text-app-subtle">{origin}{requiresOff ? ` · ${t('status.requires_dast')}` : ''}</span>
  </>
  const preparing = row.image === 'preparing' || busy === `${row.key}:prepare`
  return <li className="flex flex-wrap items-start gap-x-4 gap-y-2 py-3">
    <Switch id={`engine-${row.key}`} className="min-w-0 flex-1" checked={row.enabled} disabled={row.locked}
      onCheckedChange={onToggle} hint={hint}
      label={<>{name} <span className="font-mono text-xs text-app-muted">{row.version}</span></>} />
    <div className="ml-auto flex shrink-0 flex-col items-end gap-1 pt-0.5 text-right">
      <span className={`text-xs ${row.image_problem ? 'text-danger' : IMAGE_TONE[row.image]}`}>
        {row.image_problem ? t('image.failed', { problem: row.image_problem }) : t(IMAGE[row.image])}</span>
      {(row.image === 'missing' || (row.image_problem && row.image !== 'preparing')) &&
        <Button size="sm" variant="outline" disabled={!!busy} onClick={onPrepare} aria-label={t('image.prepare_label', { name })}>
          {preparing ? <CircleNotchIcon className="motion-safe:animate-spin" /> : <DownloadSimpleIcon />}{t('image.prepare')}</Button>}
    </div>
  </li>
}
