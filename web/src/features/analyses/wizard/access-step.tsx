import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useConfirm } from '@/shared/ui/confirm'
import { Switch } from '@/shared/ui/switch'
import { HeadersEditor } from '@/features/domains/headers-editor'
import { AddTestUserMenu, TestUserDialog } from '@/features/domains/test-users'
import { TEST_USERS_MAX, testUserSummary, type Editing } from '@/features/domains/test-users-model'
import type { Domain } from '@/features/domains/domains'
import { StepFrame } from '@/features/analyses/wizard/step-frame'
import { USERS_PER_SCAN, signInHost } from '@/features/analyses/wizard/model'

// How the scan gets past a login: test users it signs in as (each with its own crawl) and headers it sends. Going on
// with neither is allowed, but a short question says what it limits.
export function AccessStep({ domain, hosts, useHeaders, onUseHeaders, testUsers, onTestUsers, onBack, onContinue }: {
  domain: Domain; hosts: string[]; useHeaders: boolean; onUseHeaders: (use: boolean) => void; testUsers: string[]; onTestUsers: (ids: string[]) => void
  onBack: () => void; onContinue: () => void
}) {
  const { t } = useTranslation('analyses')
  const { t: ts } = useTranslation('sources')
  const confirm = useConfirm()
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState<Editing | null>(null)
  const saved = domain.headers?.length ?? 0
  const sending = useHeaders && saved > 0
  const users = domain.test_users ?? []
  const chosen = users.filter(user => testUsers.includes(user.id) && !signInHost(user, domain.host, hosts)).map(user => user.id)
  const full = chosen.length >= USERS_PER_SCAN
  const toggle = (id: string, on: boolean) => onTestUsers(on ? [...chosen, id] : chosen.filter(item => item !== id))
  const skip = async () => {
    const publicOnly = await confirm({ title: t('skip.access.title'), description: t('skip.access.text'), confirmLabel: t('skip.access.confirm'), cancelLabel: t('skip.access.back') })
    if (publicOnly) { onUseHeaders(false); onTestUsers([]); onContinue() } else setEditing({ method: 'password', user: null })
  }
  return <StepFrame title={t('access.title')} description={t('access.text')} onBack={onBack} onSkip={() => void skip()}
    onContinue={() => sending || chosen.length ? onContinue() : void skip()}>
    <section aria-labelledby="access-users" className="space-y-3">
      <div className="space-y-1">
        <h3 id="access-users" className="text-sm font-semibold">{t('access.users_title')} <span className="font-normal text-app-muted">{t('access.optional')}</span></h3>
        <p className="text-sm text-app-muted">{t('access.users_text')}</p>
      </div>
      {users.length > 0 && <fieldset className="space-y-1">
        <legend className="sr-only">{t('access.users_title')}</legend>
        {users.map(user => {
          const outside = signInHost(user, domain.host, hosts)
          const checked = chosen.includes(user.id)
          return <label key={user.id} className={`flex min-h-11 items-start gap-3 rounded-lg border px-2 py-2 ${checked ? 'border-app-fg bg-app-soft' : 'border-transparent'} ${outside || (full && !checked) ? 'text-app-muted' : 'cursor-pointer hover:bg-app-soft'}`}>
            <input type="checkbox" checked={checked} disabled={!!outside || (full && !checked)} onChange={event => toggle(user.id, event.target.checked)}
              aria-describedby={`access-user-${user.id}`} className="mt-0.5 size-4 accent-brand" />
            <span className="min-w-0 space-y-0.5">
              <span className="block text-sm font-medium break-words">{user.name}</span>
              <span id={`access-user-${user.id}`} className="block text-xs break-all text-app-muted">
                {outside ? t('access.user_outside', { host: outside }) : testUserSummary(ts, user, domain.host)}</span>
            </span>
          </label>
        })}
        <p role="status" className="px-2 text-xs text-app-muted">{full ? t('access.users_full', { max: USERS_PER_SCAN }) : ''}</p>
      </fieldset>}
      {users.length === 0 && <p className="text-sm text-app-muted">{ts('domains.test_users.empty')}</p>}
      {users.length < TEST_USERS_MAX ? <AddTestUserMenu onPick={method => setEditing({ method, user: null })} />
        : <p className="text-xs text-app-muted">{ts('domains.test_users.limit', { max: TEST_USERS_MAX })}</p>}
      {/* The crawler follows GET links as that user (log out, delete…): a warning, not a hint. Said once, for either. */}
      <p role="status" className="text-xs text-warning">{chosen.length > 0 ? t('access.test_account') : ''}</p>
    </section>
    <section aria-labelledby="access-headers" className="space-y-3 border-t border-app-line pt-5">
      <div className="space-y-1">
        <h3 id="access-headers" className="text-sm font-semibold">{t('access.headers_title')} <span className="font-normal text-app-muted">{t('access.optional')}</span></h3>
        <p className="text-sm text-app-muted">{t('access.headers_text')}</p>
      </div>
      <HeadersEditor domain={domain} admin adding={adding} onAddingChange={setAdding} />
      {saved > 0 && <div className="space-y-1.5 pt-2">
        <Switch id="use-headers" checked={useHeaders} onCheckedChange={onUseHeaders} label={t('access.use_all')} />
        <p role="status" className="pl-13 text-xs text-warning">{sending && !chosen.length ? t('access.test_account') : ''}</p>
      </div>}
    </section>
    <TestUserDialog domain={domain} editing={editing} onClose={() => setEditing(null)}
      onSaved={user => { if (!full && !signInHost(user, domain.host, hosts)) onTestUsers([...chosen, user.id]) }} />
  </StepFrame>
}
