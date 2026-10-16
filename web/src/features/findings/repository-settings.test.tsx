import { describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi, type Call, type Reply } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { RepositorySettings } from '@/features/findings/repository-settings'

const tf = (key: string, options?: Record<string, unknown>) => i18n.t(`findings:${key}`, options)
const NO_PATHS = { patterns: [], reason: null, by: null, at: null, history: [] }
const SECRETS = { rules: [], disabled_rules: [], allowlist: { regexes: [], paths: [], stopwords: [] }, history: [],
  limits: { rules: 50, entries: 100, regex: 500, description: 120 }, defaults: { rules: 0, disabled: 0, allowlist: 0 } }

function settings(routes: (call: Call) => Reply | undefined = () => undefined) {
  const calls = mockApi(call => routes(call)
    ?? (call.path.startsWith('/api/assets/exclusions?') ? { body: NO_PATHS }
    : call.path.startsWith('/api/assets/secrets') ? { body: SECRETS }
    : call.path === '/api/secrets/builtin-rules' ? { body: { rules: [{ id: 'generic-api-key', trivy: false }] } } : undefined))
  renderWithQueries(<RepositorySettings assetKey="github#7" name="org/api" kind="repository" canEdit onOpenPolicies={vi.fn()} />)
  return { calls, user: userEvent.setup() }
}

describe('excluded paths', () => {
  it('says what saving the typed paths would move, before saving, and asks why', async () => {
    const { calls, user } = settings(call => call.path === '/api/assets/exclusions/preview'
      ? { body: (call.body as { patterns: string[] }).patterns.length
        ? { excluded: 2, reopened: 0, excluded_paths: ['fixtures/a.py', 'fixtures/b.py'], reopened_paths: [], excluded_path_count: 2, reopened_path_count: 0 }
        : { excluded: 0, reopened: 0, excluded_paths: [], reopened_paths: [], excluded_path_count: 0, reopened_path_count: 0 } }
      : call.path === '/api/assets/exclusions' ? { body: { ...NO_PATHS, patterns: ['fixtures'], moved: { excluded: 2, reopened: 0 } } } : undefined)
    await user.click(await screen.findByRole('button', { name: tf('repo_settings.exclude') }))
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByText(tf('exclusions.preview.nothing'))).toBeTruthy()
    await user.type(within(dialog).getByLabelText(tf('exclusions.label')), 'fixtures')
    expect(await within(dialog).findByText(tf('exclusions.preview.excluded', { count: 2 }))).toBeTruthy()
    expect(within(dialog).getByText('fixtures/a.py')).toBeTruthy()
    expect(calls.filter(call => call.path === '/api/assets/exclusions/preview').at(-1)).toMatchObject({ action: 'preview-exclusions', body: { key: 'github#7', patterns: ['fixtures'] } })

    // With paths, the reason is required: said before sending, as the server would.
    await user.click(within(dialog).getByRole('button', { name: i18n.t('common:actions.save') }))
    expect(within(dialog).getByText(tf('exclusions.reason_needed', { min: 5 }))).toBeTruthy()
    expect(calls.some(call => call.method === 'POST' && call.path === '/api/assets/exclusions')).toBe(false)
    await user.type(within(dialog).getByLabelText(tf('exclusions.reason_required')), 'Ejemplos vulnerables a propósito')
    await user.click(within(dialog).getByRole('button', { name: i18n.t('common:actions.save') }))
    await waitFor(() => expect(calls.find(call => call.path === '/api/assets/exclusions' && call.method === 'POST')?.body)
      .toEqual({ key: 'github#7', patterns: ['fixtures'], reason: 'Ejemplos vulnerables a propósito' }))
    expect(await screen.findByText(tf('exclusions.moved_excluded', { count: 2 }))).toBeTruthy()
  })

  it('starts from the saved paths: no preview of an empty list flashes when the dialog opens', async () => {
    const saved = { ...NO_PATHS, patterns: ['fixtures'], reason: 'Ejemplos', by: 'jefa', at: '2026-10-01T00:00:00Z' }
    const { calls, user } = settings(call => call.path.startsWith('/api/assets/exclusions?') ? { body: saved }
      : call.path === '/api/assets/exclusions/preview' ? { body: { excluded: 0, reopened: 0, excluded_paths: [], reopened_paths: [], excluded_path_count: 0, reopened_path_count: 0 } } : undefined)
    await user.click(await screen.findByRole('button', { name: i18n.t('common:actions.edit') }))
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByText(tf('exclusions.preview.nothing'))).toBeTruthy()
    expect(calls.filter(call => call.path === '/api/assets/exclusions/preview').map(call => (call.body as { patterns: string[] }).patterns)).toEqual([['fixtures']])
  })

  it('shows a path the server refuses while it is typed', async () => {
    const { user } = settings(call => call.path === '/api/assets/exclusions/preview'
      ? ((call.body as { patterns: string[] }).patterns.length ? { status: 400, body: { error: 'That pattern would exclude everything' } }
        : { body: { excluded: 0, reopened: 0, excluded_paths: [], reopened_paths: [], excluded_path_count: 0, reopened_path_count: 0 } }) : undefined)
    await user.click(await screen.findByRole('button', { name: tf('repo_settings.exclude') }))
    const dialog = await screen.findByRole('dialog')
    const field = within(dialog).getByLabelText(tf('exclusions.label'))
    await user.type(field, '**')
    expect(await within(dialog).findByText('That pattern would exclude everything')).toBeTruthy()
    expect(field.getAttribute('aria-invalid')).toBe('true')
  })
})

describe('excluded paths, explained', () => {
  const nothing = { excluded: 0, reopened: 0, excluded_paths: [], reopened_paths: [], excluded_path_count: 0, reopened_path_count: 0 }

  it('says in plain words what excluding does, that nothing is hidden, and what each setting is for', async () => {
    const { user } = settings(call => call.path === '/api/assets/exclusions/preview' ? { body: nothing } : undefined)
    expect(await screen.findByText(tf('repo_settings.paths_hint'))).toBeTruthy()
    expect(screen.getByText(tf('repo_settings.secrets_hint'))).toBeTruthy()
    expect(await screen.findByText(tf('repo_settings.secrets_defaults'))).toBeTruthy()
    await user.click(screen.getByRole('button', { name: tf('repo_settings.exclude') }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByRole('heading', { name: tf('exclusions.title_for', { name: 'org/api' }) })).toBeTruthy()
    expect(within(dialog).getByText(tf('exclusions.dialog_help'))).toBeTruthy()
  })

  it('adds an example as a line, and one limited to a rule is a path and that rule', async () => {
    const { calls, user } = settings(call => call.path === '/api/assets/exclusions/preview'
      ? { body: (call.body as { patterns: string[] }).patterns.length ? { ...nothing, excluded: 1, excluded_paths: ['tests/settings.py'], excluded_path_count: 1 } : nothing }
      : undefined)
    await user.click(await screen.findByRole('button', { name: tf('repo_settings.exclude') }))
    const dialog = await screen.findByRole('dialog')
    const field = within(dialog).getByLabelText(tf('exclusions.label')) as HTMLTextAreaElement
    await user.click(within(dialog).getByRole('button', { name: tf('exclusions.examples.add_named', { pattern: 'tests/fixtures/**' }) }))
    await user.click(within(dialog).getByRole('button', { name: tf('exclusions.examples.add_named', { pattern: 'tests/** generic-api-key' }) }))
    expect(field.value).toBe('tests/fixtures/**\ntests/** generic-api-key')
    expect((within(dialog).getByRole('button', { name: tf('exclusions.examples.added_named', { pattern: 'tests/fixtures/**' }) }) as HTMLButtonElement).disabled).toBe(true)
    expect(within(dialog).getByText(tf('exclusions.examples.rule', { rule: 'generic-api-key', path: 'tests/**' }))).toBeTruthy()
    // What would move, with the current findings: listed in Excluded, not hidden.
    expect(await within(dialog).findByText(tf('exclusions.preview.excluded', { count: 1 }))).toBeTruthy()
    await waitFor(() => expect(calls.filter(call => call.path === '/api/assets/exclusions/preview').at(-1)?.body)
      .toEqual({ key: 'github#7', patterns: ['tests/fixtures/**', 'tests/** generic-api-key'] }))
  })

  it('shows a saved pattern limited to a rule as its path and the rule', async () => {
    settings(call => call.path.startsWith('/api/assets/exclusions?') ? { body: { ...NO_PATHS, patterns: ['tests/** generic-api-key'], reason: 'Clave de ejemplo', by: 'jefa', at: '2026-10-01T00:00:00Z' } } : undefined)
    const path = await screen.findByText('tests/**')
    expect(path.tagName).toBe('CODE')
    expect(screen.getByText('generic-api-key').tagName).toBe('CODE')
  })
})

describe('secret detection', () => {
  it('starts with silencing test secrets, then noisy built-in rules and the ones off by default, then your own detectors', async () => {
    const { user } = settings()
    await user.click(await screen.findByRole('button', { name: tf('repo_settings.customize') }))
    const dialog = await screen.findByRole('dialog')
    const titles = within(dialog).getAllByRole('heading', { level: 3 }).map(heading => heading.textContent)
    expect(titles).toEqual([tf('secret_rules.allowlist'), tf('secret_rules.disabled'), tf('secret_rules.opt_in'), tf('secret_rules.custom_rules')])
    // Each list says its limit, and the built-in rule picker has a visible label.
    expect(dialog.textContent).toContain(tf('secret_rules.allow_paths_help', { max: 100 }).replace(/<\/?code>/g, ''))
    expect(within(dialog).getByText(tf('secret_rules.disable_label'))).toBeTruthy()
    // Editing, the defaults are only named: a link to Policies would drop what was typed.
    expect(within(dialog).getByText(tf('repo_settings.defaults_where')).tagName).toBe('SPAN')
  })
})
