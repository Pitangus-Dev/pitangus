import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useConfirm } from '@/shared/ui/confirm'
import { Switch } from '@/shared/ui/switch'
import { HeadersEditor } from '@/features/domains/headers-editor'
import type { Domain } from '@/features/domains/domains'
import { StepFrame } from '@/features/analyses/wizard/step-frame'

// Headers to reach what's behind a login. Going on without any is allowed, but a short question says what it limits.
export function AccessStep({ domain, useHeaders, onUseHeaders, onBack, onContinue }: {
  domain: Domain; useHeaders: boolean; onUseHeaders: (use: boolean) => void; onBack: () => void; onContinue: () => void
}) {
  const { t } = useTranslation('analyses')
  const confirm = useConfirm()
  const [adding, setAdding] = useState(false)
  const saved = domain.headers?.length ?? 0
  const sending = useHeaders && saved > 0
  const skip = async () => {
    const publicOnly = await confirm({ title: t('skip.access.title'), description: t('skip.access.text'), confirmLabel: t('skip.access.confirm'), cancelLabel: t('skip.access.back') })
    if (publicOnly) { onUseHeaders(false); onContinue() } else setAdding(true)
  }
  return <StepFrame title={t('access.title')} description={t('access.text')} onBack={onBack} onSkip={() => void skip()} onContinue={() => sending ? onContinue() : void skip()}>
    <HeadersEditor domain={domain} admin adding={adding} onAddingChange={setAdding} />
    {saved > 0 && <div className="space-y-1.5 pt-2">
      <Switch id="use-headers" checked={useHeaders} onCheckedChange={onUseHeaders} label={t('access.use_all')} />
      {/* The crawler follows GET links as that user (log out, delete…): a warning, not a hint. */}
      <p role="status" className="pl-13 text-xs text-warning">{sending ? t('access.test_account') : ''}</p>
    </div>}
  </StepFrame>
}
