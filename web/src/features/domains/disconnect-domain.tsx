import { useTranslation } from 'react-i18next'
import { Button } from '@/shared/ui/button'
import type { Domain } from '@/features/domains/domains'

// The end of a domain's overview, for administrators: what disconnecting it deletes (its configuration) and what stays
// (its runs and findings, as evidence: pitangus/app/api/sources.py, domain_remove), and the button that asks once more.
export function DisconnectDomain({ domain, busy, error, onDisconnect }: { domain: Domain; busy: boolean; error: string; onDisconnect: () => void }) {
  const { t } = useTranslation('sources')
  const runs = domain.runs ?? 0
  // A surface is never scanned: it has no headers, test users, scope or schedule to lose.
  const scannable = domain.kind !== 'surface'
  return <section aria-labelledby="domain-disconnect" className="space-y-3 rounded-xl border border-danger-line p-4">
    <h2 id="domain-disconnect" className="text-base font-semibold text-danger">{t('domains.disconnect.title')}</h2>
    <p className="text-sm text-app-secondary">{scannable || runs > 0 ? t('domains.disconnect.text', { host: domain.host }) : t('domains.disconnect.text_only', { host: domain.host })}</p>
    {scannable && <ul className="list-disc space-y-0.5 pl-5 text-sm text-app-secondary">
      <li>{t('domains.disconnect.headers')}</li>
      <li>{t('domains.disconnect.users')}</li>
      <li>{t('domains.disconnect.scope')}</li>
      <li>{t('domains.disconnect.schedule')}</li>
    </ul>}
    {runs > 0 && <p className="text-sm text-app-secondary">{t('domains.disconnect.runs', { count: runs })}</p>}
    <p className="text-sm text-app-muted">{runs > 0 ? t('domains.disconnect.final_runs', { host: domain.host }) : t('domains.disconnect.final')}</p>
    {error && <p role="alert" className="text-sm text-danger">{error}</p>}
    <Button variant="outline" disabled={busy} onClick={onDisconnect} className="border-danger-line text-danger hover:text-danger dark:border-danger-line">{t('domains.disconnect.button')}</Button>
  </section>
}
