import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { CircleNotchIcon, DownloadSimpleIcon, ShieldCheckIcon } from '@phosphor-icons/react'
import { apiPost } from '@/shared/api/client'
import { ApiError } from '@/shared/api/http'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, dialogFullOnMobile } from '@/shared/ui/dialog'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/shared/ui/tabs'
import { CopyField } from '@/features/domains/copy-field'
import { proofOf, untilOf, type Domain, type ProofMethod } from '@/features/domains/domains'
import { Notice } from '@/shared/ui/notice'

const FILE_NAME = 'pitangus-verify.txt'

function download(content: string) {
  const url = URL.createObjectURL(new Blob([`${content}\n`], { type: 'text/plain' }))
  const link = document.createElement('a')
  link.href = url
  link.download = FILE_NAME
  document.body.append(link)
  link.click()
  link.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000)
}

// Proving control of a domain: a DNS TXT record (covers subdomains), a file or a meta tag (the exact host only).
export function VerifyDomainDialog({ domain, onOpenChange, onVerified, onStartScan }: {
  domain: Domain | null; onOpenChange: (open: boolean) => void; onVerified: (domain: Domain) => void; onStartScan?: (domain: Domain) => void
}) {
  const { t } = useTranslation('sources')
  return <Dialog open={!!domain} onOpenChange={onOpenChange}><DialogContent className={`max-w-xl ${dialogFullOnMobile}`}>
    {domain && <>
      <DialogHeader><DialogTitle>{t('domains.verify.title', { host: domain.host })}</DialogTitle><DialogDescription className="sr-only">{t('domains.verify.tabs_label')}</DialogDescription></DialogHeader>
      <VerifyBody domain={domain} onClose={() => onOpenChange(false)} onVerified={onVerified} onStartScan={onStartScan} />
    </>}
  </DialogContent></Dialog>
}

function VerifyBody({ domain, onClose, onVerified, onStartScan }: { domain: Domain; onClose: () => void; onVerified: (domain: Domain) => void; onStartScan?: (domain: Domain) => void }) {
  const { t } = useTranslation('sources')
  const [method, setMethod] = useState<ProofMethod>(domain.verified ? proofOf(domain) : 'dns')
  const verify = useMutation({
    mutationFn: (chosen: ProofMethod) => apiPost('/api/domains/verify', 'verify-domain', { domain_id: domain.id, method: chosen }),
    onSuccess: onVerified,
  })
  const done = verify.data

  if (done) return <>
    <Notice role="status" tone="ok">
      <span className="block font-medium">{t('domains.verify.done', { host: done.host })}</span><span className="text-app-muted">{t('domains.verify.until', { date: untilOf(done) })}</span>
    </Notice>
    <DialogFooter>
      <Button variant="ghost" onClick={onClose}>{t('common:actions.close')}</Button>
      {onStartScan && done.kind !== 'surface' && <Button autoFocus onClick={() => { onClose(); onStartScan(done) }}>{t('domains.verify.start_scan')}</Button>}
    </DialogFooter>
  </>

  // A missing proof gets our one-line reason; the server's sentence underneath says exactly what it saw.
  const failure = verify.error instanceof ApiError && verify.error.status === 400 && verify.variables
    ? { title: verify.variables === 'dns' ? t('domains.verify.failed_dns', { name: domain.txt_name ?? '' })
        : verify.variables === 'file' ? t('domains.verify.failed_file', { url: domain.verify_file_url ?? '' })
        : t('domains.verify.failed_meta', { url: domain.url }), detail: verify.error.message }
    : verify.error ? { title: verify.error.message, detail: '' } : null
  return <>
    <Tabs value={method} onValueChange={value => { setMethod(value as ProofMethod); verify.reset() }}>
      <TabsList aria-label={t('domains.verify.tabs_label')} className="w-full">
        <TabsTrigger value="dns">{t('domains.verify.tab_dns')}<span className="rounded-sm border border-app-line px-1 text-[11px] text-app-muted">{t('domains.verify.recommended')}</span></TabsTrigger>
        <TabsTrigger value="file">{t('domains.verify.tab_file')}</TabsTrigger>
        <TabsTrigger value="meta">{t('domains.verify.tab_meta')}</TabsTrigger>
      </TabsList>
      <TabsContent value="dns" className="space-y-3 pt-3">
        <p className="text-sm text-app-secondary">{t('domains.verify.dns_intro')}</p>
        <CopyField label={t('domains.verify.type')} value="TXT" />
        <CopyField label={t('domains.verify.name')} value={domain.txt_name ?? ''} />
        <CopyField label={t('domains.verify.value')} value={domain.txt_value ?? ''} />
        <p className="text-xs text-app-muted">{t('domains.verify.dns_covers')}</p>
      </TabsContent>
      <TabsContent value="file" className="space-y-3 pt-3">
        <p className="text-sm text-app-secondary">{t('domains.verify.file_intro')}</p>
        <CopyField label={t('domains.verify.path')} value={domain.verify_file_url ?? ''} />
        <CopyField label={t('domains.verify.content')} value={domain.verify_token ?? ''} />
        <Button type="button" variant="outline" size="sm" onClick={() => download(domain.verify_token ?? '')}><DownloadSimpleIcon aria-hidden />{t('domains.verify.download')}</Button>
        <p className="text-xs text-app-muted">{t('domains.verify.exact_host', { host: domain.host })}</p>
      </TabsContent>
      <TabsContent value="meta" className="space-y-3 pt-3">
        <p className="text-sm text-app-secondary">{t('domains.verify.meta_intro')}</p>
        <CopyField label={t('domains.verify.tag')} value={domain.verify_meta ?? ''} />
        <p className="text-xs text-app-muted">{t('domains.verify.exact_host', { host: domain.host })}</p>
      </TabsContent>
    </Tabs>
    {failure && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft p-3 text-sm text-danger"><p>{failure.title}</p>{failure.detail && <p className="mt-1 text-xs">{failure.detail}</p>}</div>}
    <DialogFooter>
      <Button variant="ghost" onClick={onClose}>{t('domains.verify.later')}</Button>
      <Button disabled={verify.isPending} onClick={() => verify.mutate(method)}>{verify.isPending ? <CircleNotchIcon className="motion-safe:animate-spin" aria-hidden /> : <ShieldCheckIcon aria-hidden />}{t('domains.verify.submit')}</Button>
    </DialogFooter>
  </>
}
