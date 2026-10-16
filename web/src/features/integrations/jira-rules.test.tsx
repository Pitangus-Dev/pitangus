import { describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { choose } from '@/shared/test/select'
import type { JiraRouting } from '@/shared/api/queries'
import { RuleEditor, RulesSection } from '@/features/integrations/jira-rules'
import { globMatch, resolveRule, type JiraRule } from '@/features/integrations/jira-routing'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`integrations:${key}`, options)
const rule = (id: string, name: string, extra: Partial<JiraRule> = {}): JiraRule => ({
  id, name, assets: [], patterns: [], destination: 'd1', mode: 'manual', min_severity: 'high', backfill: false, enabled: true, ...extra,
})
// The live region that says what a rule will do.
const outcome = () => screen.getAllByRole('status').map(node => node.textContent ?? '').join(' ')
const ROUTING: JiraRouting = {
  destinations: [{ id: 'd1', name: 'Payments', project: { key: 'PAY', name: 'Payments' }, issue_type: { name: 'Bug' }, mapping: {}, on_fixed: { label: 'pitangus-fixed', status: null } }],
  rules: [rule('a1', 'Payments', { patterns: ['org/payments-*'] }), rule('b2', 'Identity', { assets: ['github#7'] }), rule('default', 'Every other repository', { default: true, enabled: false, destination: null })],
  history: [], limits: { destinations: 20, rules: 50, assets: 200, patterns: 20 },
}

describe('routing rules', () => {
  it('match like the server: first enabled rule with a destination wins, patterns ignore case', () => {
    expect(globMatch('org/payments-*', 'org/payments-api')).toBe(true)
    expect(globMatch('org/pay?ents-[!x]*', 'org/payments-api')).toBe(true)
    expect(globMatch('org/payments-*', 'org/identity')).toBe(false)
    expect(resolveRule(ROUTING, 'github#9', 'Org/Payments-Web')?.id).toBe('a1')
    expect(resolveRule(ROUTING, 'github#7', 'org/identity')?.id).toBe('b2')
    expect(resolveRule(ROUTING, 'github#8', 'org/other')).toBeNull()
  })

  it('move with buttons, and the default rule stays last without them', async () => {
    const reordered = { ...ROUTING, rules: [ROUTING.rules[1], ROUTING.rules[0], ROUTING.rules[2]] }
    const calls = mockApi(call => call.path === '/api/integrations/jira/rules/order' ? { body: reordered } : { body: { items: [], total: 0, limit: 1, offset: 0 } })
    const user = userEvent.setup()
    renderWithQueries(<RulesSection routing={ROUTING} backfills={[]} onRemove={() => {}} />)

    expect(screen.getByRole('button', { name: tr('jira.rules.move_up', { name: 'Payments' }) }).hasAttribute('disabled')).toBe(true)
    expect(screen.getByRole('button', { name: tr('jira.rules.move_down', { name: 'Identity' }) }).hasAttribute('disabled')).toBe(true)
    expect(screen.queryByRole('button', { name: tr('jira.rules.move_up', { name: 'Every other repository' }) })).toBeNull()
    await user.click(screen.getByRole('button', { name: tr('jira.rules.move_up', { name: 'Identity' }) }))

    expect(calls.filter(call => call.path === '/api/integrations/jira/rules/order')).toEqual([
      { method: 'POST', path: '/api/integrations/jira/rules/order', action: 'jira-routing', body: { ids: ['b2', 'a1'] } }])
    expect(await screen.findByText(tr('jira.rules.moved', { name: 'Identity', position: 1 }))).toBeTruthy()
  })

  it('show how a backfill is going', () => {
    mockApi(() => ({ body: { items: [], total: 0, limit: 1, offset: 0 } }))
    renderWithQueries(<RulesSection routing={ROUTING} onRemove={() => {}} backfills={[{ rule: 'a1', queued: 10, findings: 14, created: 6, existing: 1, skipped: 0, failed: 1, pending: 2, truncated: false, last_error: 'Jira responded 400' }]} />)
    const status = screen.getAllByRole('status').find(item => item.textContent?.includes(tr('jira.backfill.running', { count: 10 })))!
    expect(status.textContent).toContain(tr('jira.backfill.running', { count: 10 }))
    expect(status.textContent).toContain(tr('jira.backfill.pending', { count: 2 }))
    expect(status.textContent).toContain(tr('jira.backfill.last_error', { error: 'Jira responded 400' }))
  })

  it('once done, links the issues it created and groups why the others failed', () => {
    mockApi(() => ({ body: { items: [], total: 0, limit: 1, offset: 0 } }))
    const issues = [{ key: 'PD-1', url: 'https://acme.atlassian.net/browse/PD-1' }, { key: 'PD-2', url: 'https://acme.atlassian.net/browse/PD-2' }]
    renderWithQueries(<RulesSection routing={ROUTING} onRemove={() => {}} backfills={[{ rule: 'a1', queued: 9, findings: 9, created: 6, existing: 0, skipped: 0, failed: 3, pending: 0,
      truncated: false, finished_at: '2026-10-11T22:22:00Z', last_error: 'Jira responded 400', issues, errors: [{ error: 'Jira responded 400', count: 3 }] }]} />)
    expect(screen.getByText(new RegExp(tr('jira.backfill.created', { count: 6 })))).toBeTruthy()
    expect(screen.getByRole('link', { name: 'PD-1' }).getAttribute('href')).toBe('https://acme.atlassian.net/browse/PD-1')
    expect(screen.getByText(new RegExp(tr('jira.backfill.more', { count: 4 })))).toBeTruthy()
    // The reasons, counted, instead of only the last error.
    expect(screen.getByText(tr('jira.backfill.error', { error: 'Jira responded 400', count: 3 }))).toBeTruthy()
    expect(screen.queryByText(tr('jira.backfill.last_error', { error: 'Jira responded 400' }))).toBeNull()
  })

  it('preview what a backfill would create before saving an automatic rule', async () => {
    const sample = { asset: 'org/web', summary: 'Alta · starlette 0.37.2 → 1.3.1 · org/web (poetry.lock)', lines: ['Actualiza fastapi primero.', '- Repositorio: org/web'], findings: 3 }
    const preview = { assets: 2, findings: 9, issues: 5, linked: 3, truncated: false, sample }
    const calls = mockApi(call => {
      if (call.path === '/api/integrations/jira/rules/preview') return { body: preview }
      if (call.path === '/api/integrations/jira/rules') return { body: { rule: rule('c3', 'Web', { mode: 'auto', backfill: true }), backfill: { rule: 'c3', queued: 5 }, routing: ROUTING } }
    })
    const saved = vi.fn()
    const user = userEvent.setup()
    renderWithQueries(<RuleEditor rule={null} routing={ROUTING} onClose={() => {}} onSaved={saved} />)
    await user.type(screen.getByLabelText(tr('jira.rules.name')), 'Web')
    await user.type(screen.getByLabelText(tr('jira.rules.patterns')), 'org/web-*')
    await user.click(screen.getByRole('radio', { name: new RegExp(tr('jira.rules.mode_auto_help').slice(0, 20)) }))
    await choose(user, screen.getByLabelText(tr('jira.rules.min_severity')), tr('jira.rules.at_least', { severity: i18n.t('common:severity.critical') }))
    await user.click(screen.getByLabelText(new RegExp(tr('jira.rules.backfill'))))
    expect(screen.getByText(tr('jira.preview.needed'))).toBeTruthy()

    // Saving first checks what it would create; nothing is saved yet.
    await user.click(screen.getByRole('button', { name: tr('jira.preview.run') }))
    const body = { name: 'Web', assets: [], patterns: ['org/web-*'], destination: 'd1', mode: 'auto', min_severity: 'critical', backfill: true, enabled: true }
    // What the rule will do, in one sentence: how many issues now, where, for which findings; and the counts behind it.
    await vi.waitFor(() => expect(outcome()).toContain(tr('jira.preview.now', { count: 5, issues: '5', target: 'PAY · Bug', severity: i18n.t('common:severity.critical').toLowerCase() }).replace('<scope/>', 'org/web-*')))
    expect(outcome()).toContain(tr('jira.preview.counts', { findings: '9', assets: '2', linked: '3' }))
    // And how the most severe of those issues will read in Jira.
    expect(screen.getByText(sample.summary)).toBeTruthy()
    expect(screen.getByText('Actualiza fastapi primero.')).toBeTruthy()
    expect(screen.getByText(tr('jira.preview.sample_findings', { count: 3 }))).toBeTruthy()
    expect(calls.map(call => call.path)).toEqual(['/api/integrations/jira/rules/preview'])
    expect(calls[0]).toMatchObject({ action: 'jira-preview', body })

    await user.click(screen.getByRole('button', { name: tr('jira.rules.save_backfill', { count: 5 }) }))
    await vi.waitFor(() => expect(saved).toHaveBeenCalledOnce())
    expect(calls[1]).toMatchObject({ path: '/api/integrations/jira/rules', action: 'jira-routing', body })
  })

  it('asks for a new preview when the rule changes after it', async () => {
    mockApi(call => call.path === '/api/integrations/jira/rules/preview' ? { body: { assets: 1, findings: 0, issues: 0, linked: 4, truncated: false } } : undefined)
    const user = userEvent.setup()
    renderWithQueries(<RuleEditor rule={rule('a1', 'Payments', { patterns: ['org/payments-*'], mode: 'auto', backfill: true })} routing={ROUTING} onClose={() => {}} onSaved={() => {}} />)
    await user.click(screen.getAllByRole('button', { name: tr('jira.preview.run') })[0])
    await vi.waitFor(() => expect(outcome()).toContain(tr('jira.preview.none_now', { target: 'PAY · Bug', severity: i18n.t('common:severity.high').toLowerCase() }).replace('<scope/>', 'org/payments-*')))
    await choose(user, screen.getByLabelText(tr('jira.rules.min_severity')), tr('jira.rules.at_least', { severity: i18n.t('common:severity.low') }))
    expect(screen.getByText(tr('jira.preview.outdated'))).toBeTruthy()
  })

  it('an automatic rule without backfill is checked too: nothing now, future findings as they appear', async () => {
    const calls = mockApi(call => {
      if (call.path === '/api/integrations/jira/rules/preview') return { body: { assets: 1, findings: 4, issues: 2, linked: 0, truncated: false } }
      if (call.path === '/api/integrations/jira/rules') return { body: { rule: rule('c3', 'Web', { mode: 'auto' }), backfill: null, routing: ROUTING } }
    })
    const saved = vi.fn()
    const user = userEvent.setup()
    renderWithQueries(<RuleEditor rule={rule('a1', 'Payments', { patterns: ['org/payments-*'], mode: 'auto' })} routing={ROUTING} onClose={() => {}} onSaved={saved} />)
    // The first click on Save checks what it would do; nothing is saved until it is read.
    await user.click(screen.getByRole('button', { name: tr('jira.rules.save') }))
    await vi.waitFor(() => expect(outcome()).toContain(tr('jira.preview.future_only', { target: 'PAY · Bug', severity: i18n.t('common:severity.high').toLowerCase() }).replace('<scope/>', 'org/payments-*')))
    expect(outcome()).toContain(tr('jira.preview.open_waiting', { count: 4, findings: '4', backfill: tr('jira.rules.backfill') }))
    expect(calls.map(call => call.path)).toEqual(['/api/integrations/jira/rules/preview'])
    await user.click(screen.getByRole('button', { name: tr('jira.rules.save') }))
    await vi.waitFor(() => expect(saved).toHaveBeenCalledOnce())
    expect(calls[1]).toMatchObject({ path: '/api/integrations/jira/rules', body: { mode: 'auto', backfill: false } })
  })

  it('a manual rule says where its issues go and saves without a check', async () => {
    const calls = mockApi(call => call.path === '/api/integrations/jira/rules' ? { body: { rule: rule('a1', 'Payments'), backfill: null, routing: ROUTING } } : undefined)
    const saved = vi.fn()
    const user = userEvent.setup()
    renderWithQueries(<RuleEditor rule={rule('a1', 'Payments', { patterns: ['org/payments-*'] })} routing={ROUTING} onClose={() => {}} onSaved={saved} />)
    expect(screen.getByRole('group', { name: tr('jira.rules.mode') }).textContent).toContain(tr('jira.preview.manual', { target: 'PAY · Bug' }).replace('<scope/>', 'org/payments-*'))
    await user.click(screen.getByRole('button', { name: tr('jira.rules.save') }))
    await vi.waitFor(() => expect(saved).toHaveBeenCalledOnce())
    expect(calls.map(call => call.path)).toEqual(['/api/integrations/jira/rules'])
  })

  it('a rule without a name or repositories shows each error next to its field', async () => {
    mockApi(call => call.path === '/api/integrations/jira/rules'
      ? { status: 400, body: { detail: 'Invalid rule', errors: [{ field: 'name', error: 'Give it a name' }, { field: 'assets', error: 'Choose repositories or patterns' }] } } : undefined)
    const user = userEvent.setup()
    renderWithQueries(<RuleEditor rule={null} routing={ROUTING} onClose={() => {}} onSaved={() => {}} />)
    await user.click(screen.getByRole('button', { name: tr('jira.rules.save') }))
    expect(await screen.findByText('Give it a name')).toBeTruthy()
    expect(screen.getByLabelText(tr('jira.rules.name')).getAttribute('aria-invalid')).toBe('true')
    expect(screen.getByText('Choose repositories or patterns')).toBeTruthy()
  })

  it('creating issues again for a rule saved without backfill says what it will create now, not to check a box', async () => {
    const routing = { ...ROUTING, rules: [rule('a1', 'Payments', { patterns: ['org/payments-*'], mode: 'auto' }), ...ROUTING.rules.slice(1)] }
    mockApi(call => call.path === '/api/integrations/jira/rules/preview' ? { body: { assets: 1, findings: 4, issues: 2, linked: 0, truncated: false } } : { body: { items: [], total: 0, limit: 1, offset: 0 } })
    const user = userEvent.setup()
    renderWithQueries(<RulesSection routing={routing} backfills={[]} onRemove={() => {}} />)
    await user.click(screen.getByRole('button', { name: tr('jira.rules.actions', { name: 'Payments' }) }))
    await user.click(await screen.findByRole('menuitem', { name: tr('jira.rules.rerun_backfill') }))
    await vi.waitFor(() => expect(outcome()).toContain(tr('jira.preview.now', { count: 2, issues: '2', target: 'PAY · Bug', severity: i18n.t('common:severity.high').toLowerCase() }).replace('<scope/>', 'org/payments-*')))
    expect(outcome()).not.toContain(tr('jira.rules.backfill'))
    expect(screen.getByRole('button', { name: tr('jira.rules.rerun_confirm', { count: 2 }) })).toBeTruthy()
  })
})
