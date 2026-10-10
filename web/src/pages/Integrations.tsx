import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { SessionUser } from '@/features/auth/session'
import { CodeProviders } from '@/features/sources/code-providers'
import { IssueTracking } from '@/features/integrations/jira'
import { Registries } from '@/features/sources/registries'
import { Notifications } from '@/features/integrations/notifications'
import { Button } from '@/shared/ui/button'
import { SettingsRow, SettingsRows, SettingsSection } from '@/shared/ui/settings-list'
import { api } from '@/shared/api/http'

type ProviderStatus = { id: 'openai' | 'anthropic'; configured: boolean; env: string; owner: 'user' | 'server' | null; last4: string | null; saved_at: string | null }
const AI_PROVIDERS = [{ id: 'openai', name: 'OpenAI' }, { id: 'anthropic', name: 'Anthropic' }] as const

// Plain sections of ruled rows: code providers, registries, notifications, issue tracking and, still in the works, AI.
export function Integrations({ user }: { user: SessionUser }) {
  const { t } = useTranslation('integrations')
  const admin = user.role === 'admin'
  return <div className="max-w-5xl space-y-10">
    {!admin && <p className="text-sm text-app-muted">{t('page.read_only')}</p>}
    <CodeProviders canManage={admin} />
    <Registries canManage={admin} />
    {admin && <Notifications />}
    <IssueTracking canManage={admin} />
    <AiKeys canManage={admin} />
  </div>
}

// Nothing to set up yet. Keys saved by earlier versions are listed so they can be removed.
function AiKeys({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation('integrations')
  const [providers, setProviders] = useState<ProviderStatus[]>([])
  const [busy, setBusy] = useState('')
  const [error, setError] = useState<string | null>(null)
  const loadProviders = useCallback(() => api.get<ProviderStatus[]>('/api/providers').then(setProviders), [])
  useEffect(() => { loadProviders().catch(caught => setError(caught instanceof Error ? caught.message : String(caught))) }, [loadProviders])
  const removeKey = async (provider: ProviderStatus['id']) => {
    setBusy(provider); setError(null)
    try {
      const result = await api.post<{ providers?: ProviderStatus[] }>('/api/providers/keys', 'save-ai-key', { provider, action: 'remove' })
      if (result.providers) setProviders(result.providers); else await loadProviders()
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
    finally { setBusy('') }
  }
  return <SettingsSection id="integrations-ai" title={t('page.ai.title')} description={t('page.ai.description')}>
    {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-sm text-danger">{error}</div>}
    <SettingsRows>{AI_PROVIDERS.map(({ id, name }) => {
      const saved = providers.find(provider => provider.id === id && provider.owner === 'user')
      return <SettingsRow key={id} title={<span className="text-app-muted">{name}</span>} status={t('page.ai.soon')}
        meta={saved ? t('page.ai.saved_key', { last4: saved.last4 ?? '' }) : undefined}
        actions={saved && canManage && <Button size="sm" variant="ghost" disabled={!!busy} onClick={() => void removeKey(id)}>{t('page.ai.remove_key')}</Button>} />
    })}</SettingsRows>
    <div className="text-xs leading-5 text-app-subtle"><p>{t('page.ai.plan_intro')}</p>
      <ul className="list-disc pl-4">{[t('page.ai.plan.consent'), t('page.ai.plan.budget'), t('page.ai.plan.no_code')].map(item => <li key={item}>{item}</li>)}</ul></div>
  </SettingsSection>
}
