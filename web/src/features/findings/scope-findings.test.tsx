import { describe, expect, it } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { ALL } from '@/shared/lib/scope'
import type { SessionUser } from '@/features/auth/session'
import { ScopeFindings } from '@/features/findings/scope-findings'
import { useScopeFindings } from '@/features/findings/scope-query'

const SCOPE = { id: 'scope', type: 'asset_scope', status: 'completed', created_at: '', total: 0, truncated: false, steps: [], limitations: [], owasp_coverage: [], findings: [],
  summary: { lifecycle: { open: 0, fixed: 0, suppressed: 0, from_pr: 0, excluded: 0, by_severity: {} }, candidates: 0, sla: {},
    kpis: { active: 0, dismissed: 0, only_excluded: false, has_sla: false, overdue: 0, soon: 0, act: 0, attend: 0, critical: 0, high: 0, kev: 0, fixable: 0 } },
  by_asset: [{ key: 'github#1', name: 'org/api', kind: 'repository', open: 0, critical: 0, high: 0, fixed: 0, suppressed: 0, excluded: 0, shown: 0 }] }

const USER: SessionUser = { id: '1', username: 'ana', display_name: 'Ana', role: 'member', totp_enabled: false, last_login_at: null }

function Everything({ onOpenAsset }: { onOpenAsset: () => void }) {
  const result = useScopeFindings(ALL, 'open')
  return <ScopeFindings scope={ALL} tab="open" onTab={() => {}} result={result} user={USER} onOpenAsset={onOpenAsset} />
}

describe('a scope of several assets', () => {
  it('says so when the asset to open is gone, instead of doing nothing', async () => {
    mockApi(call => call.path.startsWith('/api/findings/scope') ? { body: SCOPE } : call.path.startsWith('/api/assets') ? { body: { items: [], total: 0 } } : undefined)
    let opened = false
    renderWithQueries(<Everything onOpenAsset={() => { opened = true }} />)
    await userEvent.setup().click(await screen.findByRole('button', { name: /org\/api/ }))
    expect((await screen.findByRole('alert')).textContent).toBe(i18n.t('findings:scope.open_gone'))
    expect(opened).toBe(false)
  })
})
