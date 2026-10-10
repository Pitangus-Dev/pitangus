import { useQuery } from '@tanstack/react-query'
import { domainScopeQuery, type DomainSchedule } from '@/shared/api/queries'
import { formatList } from '@/shared/i18n/format'
import { USERS_PER_SCAN, signInHost } from '@/features/domains/test-users-model'
import type { Domain } from '@/features/domains/domains'

// What a scheduled scan signs in with and sends: some of the domain's test users and, optionally, its saved headers.
export type ScheduleAccess = { test_users: string[]; use_headers: boolean }

export const accessOf = (schedule: DomainSchedule | null | undefined): ScheduleAccess =>
  ({ test_users: schedule?.test_users ?? [], use_headers: !!schedule?.use_headers })
export const sameAccess = (a: ScheduleAccess, b: ScheduleAccess) =>
  a.use_headers === b.use_headers && [...a.test_users].sort().join() === [...b.test_users].sort().join()

// Scheduled scans reach the domain's own host and its saved scope: the in-scope hosts, while its DNS proof covers them.
export function useScheduledHosts(domain: Domain, enabled: boolean): string[] {
  const scope = useQuery({ ...domainScopeQuery(domain.id), enabled: enabled && domain.kind !== 'surface' }).data
  return scope?.covered ? scope.hosts.filter(item => item.state === 'in_scope').map(item => item.host) : []
}

// The saved choice, minus users deleted since or now signing in outside the scheduled scope (what the server would leave out).
export function usableAccess(domain: Domain, value: ScheduleAccess, hosts: string[]): ScheduleAccess {
  const users = domain.test_users ?? []
  return { test_users: value.test_users.filter(id => users.some(user => user.id === id && !signInHost(user, domain.host, hosts))).slice(0, USERS_PER_SCAN),
    use_headers: value.use_headers && (domain.headers?.length ?? 0) > 0 }
}

// The access in words, for the schedule's summary: who it signs in as and whether it sends headers.
export function describeAccess(t: (key: string, options?: Record<string, unknown>) => string, domain: Domain, value: ScheduleAccess): string {
  // Members get no test users, only how many the schedule signs in as.
  const names = domain.test_users ? domain.test_users.filter(user => value.test_users.includes(user.id)).map(user => user.name)
    : value.test_users.length ? [t('domains.schedule.access.count', { count: value.test_users.length })] : []
  if (names.length && value.use_headers) return t('domains.schedule.access.summary_both', { names: formatList(names) })
  if (names.length) return t('domains.schedule.access.summary_users', { names: formatList(names) })
  if (value.use_headers) return t('domains.schedule.access.summary_headers')
  return t('domains.schedule.access.summary_none')
}
