import { useCallback, useId, useState, type FormEvent, type RefObject } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { LoaderCircle } from 'lucide-react'
import { apiPost, type PostResponse } from '@/shared/api/client'
import { evidenceAssetsQuery, keys } from '@/shared/api/queries'
import { Button } from '@/shared/ui/button'
import { Combobox, type ComboOption } from '@/shared/ui/combobox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'

export type RegisteredImage = PostResponse<'/api/images'>

// Adds an image to the Images page without scanning it: it can be linked to the repository it is built from (only an
// administrator links) and scanned later. Starting the scan right away is opt-in.
// `returnFocus`: where the focus goes when it closes (the button that opened it may be gone once the list reloads).
export function AddImageDialog({ open, onOpenChange, admin, repository, onAdded, returnFocus }: {
  open: boolean; onOpenChange: (open: boolean) => void; admin: boolean; repository: { key: string; name: string } | null
  onAdded: (image: RegisteredImage) => void; returnFocus: RefObject<HTMLButtonElement | null>
}) {
  const { t } = useTranslation('sources')
  const id = useId()
  const queryClient = useQueryClient()
  const preset = repository ? { id: repository.key, label: repository.name } : null
  const [reference, setReference] = useState('')
  const [built, setBuilt] = useState<ComboOption | null>(preset)
  const [scan, setScan] = useState(false)
  const [error, setError] = useState('')
  // Closing clears the form, so the next opening starts empty (with the page's repository, if one is chosen).
  const [wasOpen, setWasOpen] = useState(open)
  if (open !== wasOpen) {
    setWasOpen(open)
    if (open) { setReference(''); setBuilt(preset); setScan(false); setError('') }
  }
  const search = useCallback((q: string) => queryClient.fetchQuery(evidenceAssetsQuery(q, 'repository')).then(page => ({
    options: page.items.map(item => ({ id: item.key, label: item.name })), total: page.total })), [queryClient])
  const mutation = useMutation({
    mutationFn: () => apiPost('/api/images', 'register-image', { reference: reference.trim(), scan, ...(admin && built ? { repository: built.id } : {}) }),
    onSuccess: image => {
      void queryClient.invalidateQueries({ queryKey: keys.images })
      void queryClient.invalidateQueries({ queryKey: keys.evidence })
      if (image.run) void queryClient.invalidateQueries({ queryKey: keys.runs })
      onAdded(image)
      onOpenChange(false)
    },
    onError: caught => setError(caught instanceof Error ? caught.message : String(caught)),
  })
  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (mutation.isPending || !reference.trim()) return
    setError('')
    mutation.mutate()
  }

  return <Dialog open={open} onOpenChange={onOpenChange}><DialogContent className="max-w-lg" finalFocus={returnFocus}>
    <DialogHeader><DialogTitle>{t('images.add.title')}</DialogTitle><DialogDescription>{t('images.add.description')}</DialogDescription></DialogHeader>
    <form onSubmit={submit} className="space-y-5" aria-busy={mutation.isPending || undefined}>
      <div className="space-y-2">
        <label htmlFor={`${id}-reference`} className="text-sm text-app-secondary">{t('images.add.reference')}</label>
        <Input id={`${id}-reference`} required autoFocus value={reference} maxLength={300} spellCheck={false} autoComplete="off"
          onChange={event => setReference(event.target.value)} placeholder={t('images.add.reference_placeholder')} aria-invalid={error ? true : undefined}
          aria-describedby={error ? `${id}-error ${id}-hint` : `${id}-hint`} className="border-app-line bg-app-soft font-mono" />
        <p id={`${id}-hint`} className="text-xs text-app-muted">{t('images.add.reference_hint')}</p>
      </div>
      {admin && <div className="space-y-2">
        <span className="block text-sm text-app-secondary">{t('images.add.built_from')} <span className="text-app-muted">{t('images.add.optional')}</span></span>
        <div className="flex flex-wrap items-center gap-2">
          <Combobox className="w-full min-w-0 flex-1" label={t('images.add.built_from_label')} placeholder={t('images.add.built_from_placeholder')} emptyText={t('images.add.no_repository')}
            value={built} search={search} onSelect={setBuilt} describedBy={`${id}-built-hint`} />
          {built && <Button type="button" size="sm" variant="ghost" aria-label={t('images.add.clear_repository_for', { name: built.label })} onClick={() => setBuilt(null)}>{t('images.add.clear_repository')}</Button>}
        </div>
        <p id={`${id}-built-hint`} className="text-xs text-app-muted">{t('images.add.built_from_hint')}</p>
      </div>}
      <div className="space-y-1">
        <label className="flex min-h-6 cursor-pointer items-center gap-2 text-sm">
          <input type="checkbox" checked={scan} onChange={event => setScan(event.target.checked)} aria-describedby={`${id}-scan-hint`} className="size-4 accent-brand" />
          {t('images.add.scan_now')}
        </label>
        <p id={`${id}-scan-hint`} className="pl-6 text-xs text-app-muted">{t('images.add.scan_now_hint')}</p>
      </div>
      {error && <p id={`${id}-error`} role="alert" className="rounded-lg border border-danger-line bg-danger-soft p-3 text-sm text-danger">{error}</p>}
      <DialogFooter>
        <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>{t('common:actions.cancel')}</Button>
        <Button type="submit" disabled={mutation.isPending || !reference.trim()}>{mutation.isPending && <LoaderCircle className="motion-safe:animate-spin" aria-hidden />}{t('images.add.submit')}</Button>
      </DialogFooter>
    </form>
  </DialogContent></Dialog>
}
