import type { DomainTestUser } from '@/shared/api/queries'

export type LoginMethod = 'password' | 'password_totp'
export type Editing = { method: LoginMethod; user: DomainTestUser | null }
export const TEST_USERS_MAX = 10
export const USERS_PER_SCAN = 3   // test users one web scan signs in with

const hostOf = (url: string | null | undefined) => { try { return url ? new URL(url).hostname.toLowerCase() : '' } catch { return '' } }
// A test user signs in on a host this scan must reach (the root, or a subdomain listed by name): the one that isn't, or null.
export const signInHost = (user: { applies_to: string; login_url?: string | null }, root: string, hosts: string[]) =>
  [user.applies_to, hostOf(user.login_url)].filter(Boolean).find(host => host !== root && !hosts.includes(host)) ?? null
export const METHOD_LABEL = { password: 'domains.test_users.method.password', password_totp: 'domains.test_users.method.password_totp' } as const

export const methodOf = (method: string): LoginMethod => method === 'password_totp' ? 'password_totp' : 'password'

// What a test user is, in one muted line: who it signs in as, how, and where (when not on the domain itself).
export function testUserSummary(t: (key: string, options?: Record<string, unknown>) => string, user: DomainTestUser, root: string) {
  return [user.username, t(METHOD_LABEL[methodOf(user.method)]), ...(user.applies_to !== root ? [user.applies_to] : [])].join(' · ')
}
