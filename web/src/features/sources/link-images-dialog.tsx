import { useId, useState, type FormEvent } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { CircleNotchIcon, MagnifyingGlassIcon } from '@phosphor-icons/react'
import { apiPost } from '@/shared/api/client'
import { imagesQuery, keys } from '@/shared/api/queries'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'
import { SkeletonList } from '@/shared/ui/loading'
import { formatNumber } from '@/shared/i18n/format'
import { useDebounced } from '@/shared/lib/useDebounced'

const SHOWN = 50

// Links images to a repository from the repository's own row: the images listed (search narrows them), each with where
// it is built from now, and one action for the ones chosen. Without images, it offers adding one by its reference.
export function LinkImagesDialog({ repository, onClose, onLinked, onAddImage }: {
  repository: { key: string; name: string }; onClose: () => void; onLinked: (count: number) => void; onAddImage: () => void
}) {
  const { t } = useTranslation('sources')
  const id = useId()
  const queryClient = useQueryClient()
  const [q, setQ] = useState('')
  const [chosen, setChosen] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState(false)
  const [failed, setFailed] = useState<{ name: string; error: string }[]>([])
  const search = useDebounced(q.trim(), 250)
  // Asked again each time the dialog opens: an image added a moment ago has to be there.
  const images = useQuery({ ...imagesQuery({ q: search, limit: SHOWN }), staleTime: 0 })
  const data = images.data
  const names = new Map((data?.items ?? []).map(item => [item.key, item.name]))

  const toggle = (key: string) => setChosen(current => { const next = new Set(current); if (next.has(key)) next.delete(key); else next.add(key); return next })
  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (!chosen.size || busy) return
    setBusy(true); setFailed([])
    const errors: { key: string; name: string; error: string }[] = []
    for (const key of chosen) {
      try { await apiPost('/api/evidence/image-link', 'image-link', { image: key, repository: repository.key }) }
      catch (caught) { errors.push({ key, name: names.get(key) ?? key, error: caught instanceof Error ? caught.message : String(caught) }) }
    }
    void queryClient.invalidateQueries({ queryKey: keys.images })
    void queryClient.invalidateQueries({ queryKey: keys.evidence })
    setBusy(false)
    if (!errors.length) { onLinked(chosen.size); return }
    // What failed stays chosen, with its reason, to try again; what was linked leaves the selection.
    setChosen(new Set(errors.map(item => item.key)))
    setFailed(errors)
  }

  const empty = data && !data.items.length
  return <Dialog open onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-xl">
    <DialogHeader><DialogTitle>{t('images.link_dialog.title', { name: repository.name })}</DialogTitle>
      <DialogDescription>{t('images.link_dialog.description')}</DialogDescription></DialogHeader>
    <form onSubmit={submit} className="space-y-3" aria-busy={busy || undefined}>
      <label className="relative block"><span className="sr-only">{t('images.search')}</span>
        <MagnifyingGlassIcon className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-app-subtle" aria-hidden />
        <Input value={q} onChange={event => setQ(event.target.value)} placeholder={t('images.search_placeholder')} className="border-input bg-card pl-9" /></label>
      {images.isError ? <p role="alert" className="text-sm text-danger">{t('images.load_failed')}</p>
        : !data ? <SkeletonList rows={3} label={t('images.loading')} />
        : empty && !search ? <div className="flex flex-wrap items-center gap-2 text-sm text-app-muted"><p>{t('images.link_dialog.empty')}</p>
            <Button type="button" size="sm" variant="outline" onClick={onAddImage}>{t('images.add.open')}</Button></div>
        : empty ? <p className="py-4 text-center text-sm text-app-muted">{t('images.no_match')}</p>
        : <fieldset>
          <legend className="sr-only">{t('images.link_dialog.legend', { name: repository.name })}</legend>
          <ul className="max-h-80 divide-y divide-app-line overflow-y-auto rounded-lg border border-app-line">{data.items.map(image => {
            const here = image.built_from?.repository === repository.key
            const hint = here ? t('images.link_dialog.already') : image.built_from?.repository ? t('images.currently', { name: image.built_from.name }) : t('images.tabs.unlinked')
            return <li key={image.key}><label className={`flex min-h-6 items-start gap-3 px-3 py-2.5 ${here ? '' : 'cursor-pointer hover:bg-app-soft'}`}>
              <input type="checkbox" className="mt-0.5 size-4 accent-brand" checked={here || chosen.has(image.key)} disabled={here || busy}
                aria-describedby={`${id}-${image.key}-hint`} onChange={() => toggle(image.key)} />
              <span className="min-w-0 flex-1">
                <span className="flex min-w-0 items-center gap-2 text-sm font-medium"><span className="truncate">{image.name}</span>
                  {!image.analyzed && <span className="shrink-0 rounded-sm border border-info-line bg-info-soft px-1.5 text-[11px] font-normal text-info">{t('images.not_analyzed')}</span>}</span>
                {image.reference && <span className="block truncate font-mono text-xs text-app-muted">{image.reference}</span>}
                <span id={`${id}-${image.key}-hint`} className="block text-xs text-app-subtle">{hint}</span>
              </span></label></li>
          })}</ul>
          {data.total > data.items.length && <p className="mt-2 text-xs text-app-subtle">{t('images.link_dialog.more', { shown: formatNumber(data.items.length), total: formatNumber(data.total) })}</p>}
        </fieldset>}
      {failed.length > 0 && <ul role="alert" className="space-y-0.5 text-xs text-danger">{failed.map(item => <li key={item.name}>{t('images.link_dialog.failed', { image: item.name, error: item.error })}</li>)}</ul>}
      <DialogFooter>
        <Button type="button" variant="ghost" onClick={onClose} disabled={busy}>{t('common:actions.cancel')}</Button>
        <Button type="submit" disabled={!chosen.size || busy}>{busy && <CircleNotchIcon className="motion-safe:animate-spin" aria-hidden />}
          {t('images.link_dialog.submit', { count: chosen.size })}</Button>
      </DialogFooter>
    </form>
  </DialogContent></Dialog>
}
