import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ArrowSquareOutIcon } from '@phosphor-icons/react'
import { api } from '@/shared/api/http'
import { Button } from '@/shared/ui/button'
import { buttonVariants } from '@/shared/ui/button-variants'
import { readRoute } from '@/shared/lib/route'
import { SettingsRow, SettingsRows, SettingsSection, type StatusTone } from '@/shared/ui/settings-list'
import { GitHubAppGuide, GitHubInstall, type GitHubInstallation, type GitHubStatus } from '@/features/sources/github-setup'
import { useSourcePage } from '@/features/sources/sources'

// Providers still on the way: listed so people know, with nothing to set up yet.
const pending = [
  { id: 'gitlab', name: 'GitLab', reason: 'providers.pending.gitlab' },
  { id: 'bitbucket', name: 'Bitbucket', reason: 'providers.pending.bitbucket' },
  { id: 'azure', name: 'Azure DevOps', reason: 'providers.pending.azure' },
] as const

// Integrations → Code providers: the GitHub App (create, install, connect accounts) and what comes next.
export function CodeProviders({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation('sources')
  const [github, setGithub] = useState<GitHubStatus | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [confirmForget, setConfirmForget] = useState(false)
  // Coming back from installing the App on GitHub: the confirmation lives in the folded panel, so it opens itself.
  const [open, setOpen] = useState(() => readRoute().params.has('installation'))
  // One repository is enough to learn whether GitHub is answering for the connected accounts.
  const probe = useSourcePage({ perPage: 1 }, !!github?.connected)
  useEffect(() => { void api.get<GitHubStatus>('/api/integrations/github').then(setGithub).catch(caught => setError(caught instanceof Error ? caught.message : String(caught))) }, [])

  const act = async (action: 'disconnect' | 'forget_app', installationId?: number) => {
    setBusy(true); setError('')
    try {
      await api.post<GitHubStatus>('/api/integrations/github', 'connect-github', { action, ...(installationId ? { installation_id: installationId } : {}) })
      setConfirmForget(false)
      setGithub(await api.get<GitHubStatus>('/api/integrations/github'))
      probe.reload()
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
    finally { setBusy(false) }
  }
  const changed = (next: GitHubStatus) => { setGithub(next); probe.reload() }

  const installations = github?.installations ?? []
  const providerError = probe.data?.providers.github?.error
  const [status, tone, meta]: [string, StatusTone, string] = !github ? [error ? t('providers.row.unavailable') : '', 'danger', '']
    : providerError ? [t('providers.row.unreachable'), 'attention', providerError]
    : github.connected ? [t('providers.row.connected', { count: installations.length }), 'success', installations.map(item => item.account ?? `#${item.installation_id}`).join(', ')]
    : github.configured ? [t('providers.row.not_installed'), 'attention', github.name ?? github.slug]
    : [t('providers.status.not_configured'), 'muted', t('providers.github_tagline')]
  const label = !canManage ? t('providers.row.details') : github?.connected ? t('providers.row.manage') : github?.configured ? t('providers.row.finish') : t('providers.row.connect')

  const panel = github && <div className="space-y-5">
    {github.connected && <div className="space-y-2">
      <h4 className="text-sm font-medium">{t('providers.accounts_connected', { count: installations.length })}</h4>
      <ul className="divide-y divide-app-line border-y border-app-line">{installations.map(installation => <Installation key={installation.installation_id} installation={installation} canManage={canManage} busy={busy} onDisconnect={() => void act('disconnect', installation.installation_id)} />)}</ul>
      <p className="text-xs leading-5 text-app-subtle">{t('providers.key_note')}</p>
    </div>}
    {github.configured ? <GitHubInstall status={github} canManage={canManage} onChanged={changed} /> : <GitHubAppGuide status={github} canManage={canManage} onSaved={changed} />}
    {github.configured && github.source === 'vault' && canManage && <div className="border-t border-app-line pt-3 text-xs">
      {confirmForget ? <div className="flex flex-wrap items-center gap-2"><span className="text-app-muted">{t('providers.forget_confirm')}</span>
        <Button size="sm" variant="destructive" disabled={busy} onClick={() => void act('forget_app')}>{t('providers.forget')}</Button><Button size="sm" variant="ghost" onClick={() => setConfirmForget(false)}>{t('common:actions.cancel')}</Button></div>
        : <button type="button" onClick={() => setConfirmForget(true)} className="min-h-6 text-app-subtle hover:text-app-fg">{t('providers.use_other_app')}</button>}
    </div>}
  </div>

  return <SettingsSection id="integrations-code" title={t('providers.title')} description={t('providers.description')}>
    {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-sm text-danger">{error}</div>}
    <SettingsRows>
      <SettingsRow title="GitHub" loading={github || error ? undefined : t('providers.loading')} status={status} tone={tone} meta={meta}
        disclosure={github ? { label, content: panel, open, onOpenChange: setOpen } : undefined} />
      {pending.map(item => <SettingsRow key={item.id} title={<span className="text-app-muted">{item.name}</span>} status={t('providers.row.soon')} meta={t(item.reason)} />)}
    </SettingsRows>
  </SettingsSection>
}

function Installation({ installation, canManage, busy, onDisconnect }: { installation: GitHubInstallation; canManage: boolean; busy: boolean; onDisconnect: () => void }) {
  const { t } = useTranslation('sources')
  const manageUrl = installation.account_type === 'Organization' && installation.account
    ? `https://github.com/organizations/${encodeURIComponent(installation.account)}/settings/installations/${installation.installation_id}`
    : `https://github.com/settings/installations/${installation.installation_id}`
  const account = installation.account ?? '—'
  const scope = installation.repository_selection === 'selected' ? t('providers.scope.selected') : installation.repository_selection === 'all' ? t('providers.scope.all') : null
  return <li className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2 py-2.5">
    <div className="min-w-0"><p className="truncate text-sm">{installation.account_type === 'Organization' ? t('providers.organization_account', { account }) : account}</p>
      <p className="text-xs text-app-subtle">{[scope, t('providers.connected_by', { name: installation.connected_by ?? t('providers.unknown_person') }), <span key="id" className="font-mono">#{installation.installation_id}</span>]
        .filter(Boolean).flatMap((part, index) => index ? [' · ', part] : [part])}</p></div>
    <div className="flex flex-wrap gap-1"><a href={manageUrl} target="_blank" rel="noopener noreferrer" className={buttonVariants({ size: 'sm', variant: 'ghost' })}>{t('providers.change_repositories')} <ArrowSquareOutIcon /><span className="sr-only">{t('new_tab')}</span></a>
      {canManage && <Button size="sm" variant="ghost" disabled={busy} onClick={onDisconnect}>{t('providers.disconnect_account')}</Button>}</div>
  </li>
}
