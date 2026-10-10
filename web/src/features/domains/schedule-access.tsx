import { useTranslation } from 'react-i18next'
import { formatList } from '@/shared/i18n/format'
import { USERS_PER_SCAN, signInHost, testUserSummary } from '@/features/domains/test-users-model'
import { usableAccess, type ScheduleAccess } from '@/features/domains/schedule-access-model'
import type { Domain } from '@/features/domains/domains'

// The access part of a schedule's editor: one checkbox per test user (at most three, only those signing in on a host
// the scheduled scan reaches) and one for the saved headers. Administrators only: members get no users or headers.
export function ScheduleAccessPicker({ id, domain, value, hosts, onChange }: {
  id: string; domain: Domain; value: ScheduleAccess; hosts: string[]; onChange: (value: ScheduleAccess) => void
}) {
  const { t } = useTranslation('sources')
  const users = domain.test_users ?? []
  const headers = (domain.headers ?? []).map(item => item.name)
  const chosen = usableAccess(domain, value, hosts).test_users
  const full = chosen.length >= USERS_PER_SCAN
  const toggle = (user: string, on: boolean) => onChange({ ...value, test_users: on ? [...chosen, user] : chosen.filter(item => item !== user) })
  if (!users.length && !headers.length) return <p className="text-xs text-app-muted">{t('domains.schedule.access.none')}</p>
  return <fieldset className="space-y-2">
    <legend className="text-xs text-app-muted">{t('domains.schedule.access.legend')}</legend>
    {users.map(user => {
      const outside = signInHost(user, domain.host, hosts)
      const checked = chosen.includes(user.id)
      const disabled = !!outside || (full && !checked)
      return <label key={user.id} className={`flex min-h-6 items-start gap-2 text-sm ${disabled ? 'text-app-muted' : 'cursor-pointer text-app-fg'}`}>
        <input type="checkbox" checked={checked} disabled={disabled} onChange={event => toggle(user.id, event.target.checked)}
          aria-describedby={`${id}-user-${user.id}`} className="mt-0.5 size-4 accent-brand" />
        <span className="min-w-0">
          <span className="block break-words">{user.name}</span>
          <span id={`${id}-user-${user.id}`} className="block text-xs break-all text-app-muted">
            {outside ? t('domains.schedule.access.outside', { host: outside }) : testUserSummary(t, user, domain.host)}</span>
        </span>
      </label>
    })}
    {users.length > 0 && <p role="status" className="text-xs text-app-muted">{full ? t('domains.schedule.access.full', { max: USERS_PER_SCAN }) : ''}</p>}
    {headers.length > 0 && <label className="flex min-h-6 cursor-pointer items-start gap-2 text-sm text-app-fg">
      <input type="checkbox" checked={value.use_headers} onChange={event => onChange({ ...value, use_headers: event.target.checked })} className="mt-0.5 size-4 accent-brand" />
      <span className="min-w-0">{t('domains.schedule.access.headers', { count: headers.length, names: formatList(headers) })}</span>
    </label>}
  </fieldset>
}
