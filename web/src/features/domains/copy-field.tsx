import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Check, Copy } from 'lucide-react'
import { Button } from '@/shared/ui/button'

// One value to paste somewhere else (a DNS record, a file's content), with its own copy button and announcement.
export function CopyField({ label, value }: { label: string; value: string }) {
  const { t } = useTranslation('sources')
  const [copied, setCopied] = useState<'' | 'ok' | 'failed'>('')
  // Without clipboard access (no HTTPS, permission denied) it says so, so nobody pastes something else.
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); setCopied('ok') } catch { setCopied('failed') }
    window.setTimeout(() => setCopied(''), 2500)
  }
  return <div className="space-y-1">
    <span className="text-xs text-app-muted">{label}</span>
    <div className="flex items-center gap-2 rounded-lg border border-app-line bg-app-soft px-3 py-1.5">
      <code className="min-w-0 flex-1 font-mono text-xs break-all text-app-secondary">{value}</code>
      <Button type="button" variant="ghost" size="icon-sm" aria-label={t('domains.verify.copy', { field: label })} onClick={() => void copy()}>{copied === 'ok' ? <Check /> : <Copy />}</Button>
    </div>
    <span role="status" className={copied === 'failed' ? 'text-xs text-danger' : 'sr-only'}>{copied === 'ok' ? t('copied_to_clipboard') : copied === 'failed' ? t('domains.verify.copy_failed') : ''}</span>
  </div>
}
