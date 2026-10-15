import { describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { SecretRulesDialog, type SecretConfig } from '@/features/findings/secret-rules'
import { entryCount, secretCounts, secretSummary } from '@/features/findings/secret-summary'

const CONFIG = { allowlist: { regexes: [], paths: [], stopwords: [] }, rules: [], disabled_rules: [], enabled_rules: [], reason: null, by: null, at: null,
  history: [], limits: { rules: 50, entries: 100, regex: 500, description: 120, keywords: 10 } } as unknown as SecretConfig

describe('rules that start off', () => {
  it('turns an opt-in rule on and saves it with the settings', async () => {
    mockApi(call => call.path === '/api/secrets/builtin-rules' ? { body: { engine: 'betterleaks', version: '1.9.0', rules: [
      { id: 'github-pat', trivy: 'github-pat', opt_in: false }, { id: 'generic-password', trivy: null, opt_in: false }, { id: 'generic-credential-uri', trivy: null, opt_in: true }] } } : undefined)
    const save = vi.fn(async () => CONFIG)
    const user = userEvent.setup()
    renderWithQueries(<SecretRulesDialog open onOpenChange={() => {}} title="Secrets" description="d" config={CONFIG} canEdit save={save} onSaved={() => {}} />)
    const box = await screen.findByRole('checkbox', { name: 'generic-credential-uri' })
    expect((box as HTMLInputElement).checked).toBe(false)
    await user.click(box)
    await user.type(screen.getByLabelText(new RegExp(i18n.t('findings:secret_rules.reason'))), 'Our services keep connection strings in code')
    await user.click(screen.getByRole('button', { name: i18n.t('common:actions.save') }))
    expect(save).toHaveBeenCalledWith(expect.objectContaining({ enabled_rules: ['generic-credential-uri'], disabled_rules: [] }))
  })
})

describe('the summary of the settings', () => {
  it('counts an opt-in rule turned on, so it never reads as the defaults', () => {
    const counts = secretCounts({ ...CONFIG, enabled_rules: ['generic-credential-uri'] } as SecretConfig)
    expect(entryCount(counts)).toBe(1)
    expect(secretSummary(i18n.getFixedT('en', 'findings'), counts)).toBe(i18n.t('findings:secret_rules.count_enabled', { lng: 'en', count: 1 }))
  })
})
