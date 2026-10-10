import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { CheckIcon, CircleNotchIcon, CopyIcon } from '@phosphor-icons/react'
import { api } from '@/shared/api/http'
import { keys, type Egress } from '@/shared/api/queries'
import { Button } from '@/shared/ui/button'

// Which addresses a site that filters by IP has to allow, in plain sight under the review of a web scan. Declared by
// the server; otherwise an administrator can ask once (the server queries a public echo service), and a member is
// told who to ask.
export function EgressNote({ egress, admin }: { egress: Egress | null | undefined; admin: boolean }) {
  const { t } = useTranslation('analyses')
  const queryClient = useQueryClient()
  const [copied, setCopied] = useState<'' | 'ok' | 'failed'>('')
  const detect = useMutation({
    mutationFn: () => api.post<Egress>('/api/domains/egress', 'detect-egress', {}),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: keys.domains }),
  })
  const ips = egress?.ips ?? []
  const copy = async () => {
    try { await navigator.clipboard.writeText(ips.join(', ')); setCopied('ok') } catch { setCopied('failed') }
    window.setTimeout(() => setCopied(''), 2500)
  }
  if (ips.length) {
    return <div className="space-y-1">
      <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-app-secondary">
        <span>{t('review.egress.allow')}</span>
        <code className="font-mono text-xs break-all text-app-fg">{ips.join(', ')}</code>
        <Button type="button" size="xs" variant="ghost" aria-label={t('review.egress.copy_label')} onClick={() => void copy()}>
          {copied === 'ok' ? <CheckIcon aria-hidden /> : <CopyIcon aria-hidden />}{t('review.egress.copy')}</Button>
      </p>
      <span role="status" className={copied === 'failed' ? 'text-xs text-danger' : 'sr-only'}>{copied === 'ok' ? t('review.egress.copied') : copied === 'failed' ? t('review.egress.copy_failed') : ''}</span>
    </div>
  }
  if (!admin) return <p className="text-sm text-app-muted">{t('review.egress.ask_admin')}</p>
  return <div className="space-y-1">
    <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-app-secondary">
      <span>{t('review.egress.unknown')}</span>
      <Button type="button" size="xs" variant="outline" disabled={detect.isPending} onClick={() => detect.mutate()}>
        {detect.isPending && <CircleNotchIcon className="motion-safe:animate-spin" aria-hidden />}{t('review.egress.detect')}</Button>
    </p>
    <p className="text-xs text-app-muted">{t('review.egress.detect_hint')}</p>
    {detect.isError && <p role="alert" className="text-xs text-danger">{detect.error.message}</p>}
  </div>
}
