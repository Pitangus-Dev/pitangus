import { useCallback, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Boxes, LoaderCircle, Search, X } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Combobox } from '@/shared/ui/combobox'
import { Input } from '@/shared/ui/input'
import { SkeletonList } from '@/shared/ui/loading'
import { api } from '@/shared/api/http'
import { imagesQuery, keys, type ImageLink } from '@/shared/api/queries'
import { formatDay, formatNumber } from '@/shared/i18n/format'
import { ImageOrigin } from '@/features/compliance/image-origin'
import { Pager } from '@/features/sources/source-search'

const PAGE_SIZE = 25
export type RepositoryFilter = { key: string; name: string }

// Analyzed images and where each is built from: its OCI label links it on its own, an administrator links (or relinks)
// it by hand when the label is missing or wrong. Filtered by a repository, it lists the images built from it and lets an
// administrator link one more.
export function ImageList({ admin, repository, onClearRepository, onOpenFindings, onNew }: {
  admin: boolean; repository: RepositoryFilter | null; onClearRepository: () => void; onOpenFindings: (key: string) => void; onNew: () => void
}) {
  const { t } = useTranslation('sources')
  const queryClient = useQueryClient()
  const searchBox = useRef<HTMLInputElement>(null)
  const [link, setLink] = useState<ImageLink>('all')
  const [q, setQ] = useState('')
  const [page, setPage] = useState(1)
  const [rescans, setRescans] = useState<Record<string, 'busy' | 'queued' | { error: string }>>({})
  const [announce, setAnnounce] = useState('')
  const [linkError, setLinkError] = useState('')
  const images = useQuery(imagesQuery({ q, link, repository: repository?.key, offset: (page - 1) * PAGE_SIZE, limit: PAGE_SIZE }))
  const data = images.data
  // With a repository chosen every image listed is linked to it: the "not linked" tab could only ever be empty.
  const tabs: ImageLink[] = repository ? ['all', 'label', 'manual'] : ['all', 'unlinked', 'label', 'manual']

  // Images not linked yet come first; the ones built from another repository say so, so nothing is moved unseen.
  const searchImages = useCallback((query: string) => queryClient.fetchQuery(imagesQuery({ q: query, limit: 20 })).then(found => {
    const options = found.items.filter(item => item.built_from?.repository !== repository?.key)
      .sort((a, b) => Number(Boolean(a.built_from?.repository)) - Number(Boolean(b.built_from?.repository)))
      .map(item => ({ id: item.key, label: item.name, hint: item.built_from?.repository ? t('images.currently', { name: item.built_from.name }) : t('images.tabs.unlinked') }))
    return { options, total: found.total - (found.items.length - options.length) }
  }), [queryClient, repository?.key, t])
  const changed = (message: string) => {
    setAnnounce(message)
    void queryClient.invalidateQueries({ queryKey: keys.images })
    void queryClient.invalidateQueries({ queryKey: keys.evidence })
    // The row may leave the list (another tab, another repository): the focus goes back to the search box.
    searchBox.current?.focus()
  }
  const linkImage = async (image: { id: string; label: string }) => {
    if (!repository) return
    setLinkError('')
    try {
      await api.post('/api/evidence/image-link', 'image-link', { image: image.id, repository: repository.key })
      changed(t('images.linked', { image: image.label, name: repository.name }))
    } catch (caught) { setLinkError(caught instanceof Error ? caught.message : String(caught)) }
  }
  const rescan = async (key: string, name: string, reference: string) => {
    setRescans(current => ({ ...current, [key]: 'busy' }))
    try {
      await api.post('/api/images/scans', 'scan-image', { reference })
      setRescans(current => ({ ...current, [key]: 'queued' }))
      setAnnounce(t('images.queued_for', { name }))
      void queryClient.invalidateQueries({ queryKey: keys.runs })
    } catch (caught) { setRescans(current => ({ ...current, [key]: { error: caught instanceof Error ? caught.message : String(caught) } })) }
  }
  const choose = (next: ImageLink) => { setLink(next); setPage(1) }
  const empty = !data ? null : repository && !data.counts.all
    ? <p className="text-sm text-app-muted">{t('images.none_for_repository', { name: repository.name })}{admin ? ` ${t('images.none_for_repository_admin')}` : ''}</p>
    : !data.counts.all ? <p className="text-sm text-app-muted">{t('images.none')} <button type="button" onClick={onNew} className="min-h-6 text-brand underline-offset-2 hover:underline">{t('images.new_scan')}</button></p>
    : !data.items.length ? <p className="p-6 text-center text-sm text-app-muted">{t('images.no_match')}</p> : null

  return <Card className="border-app-line bg-panel">
    <CardHeader><CardTitle className="text-base">{t('images.title')}</CardTitle><CardDescription>{t('images.description')}</CardDescription></CardHeader>
    <CardContent className="space-y-4">
      {repository && <div className="flex flex-wrap items-center gap-3 rounded-xl border border-app-line bg-inset px-3 py-2 text-sm">
        <span className="flex min-w-0 items-center gap-1 rounded-lg border border-app-line bg-panel py-0.5 pr-1 pl-2">
          <span className="min-w-0 truncate">{t('images.built_from', { name: repository.name })}</span>
          <button type="button" aria-label={t('images.clear_repository')} onClick={() => { onClearRepository(); searchBox.current?.focus() }}
            className="grid size-6 shrink-0 place-items-center rounded-md text-app-muted hover:bg-app-soft hover:text-app-fg"><X className="size-3.5" aria-hidden /></button></span>
        {admin && <Combobox className="w-full min-w-0 max-w-sm flex-1 sm:min-w-64" label={t('images.link_label', { name: repository.name })} placeholder={t('images.link')} emptyText={t('images.no_match')}
          value={null} search={searchImages} onSelect={option => void linkImage(option)} />}
        {linkError && <p role="alert" className="w-full text-xs text-danger">{linkError}</p>}
      </div>}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div role="group" aria-label={t('images.filter')} className="flex flex-wrap gap-2">{tabs.map(tab => <Button key={tab} size="sm" variant="outline" aria-pressed={link === tab} onClick={() => choose(tab)}
          className={link === tab ? 'border-brand/60 bg-brand/10 text-brand' : 'border-app-line bg-app-soft'}>
          {t(`images.tabs.${tab}`)}{data ? ` · ${formatNumber(data.counts[tab])}` : ''}</Button>)}</div>
        <label className="relative w-full max-w-xs"><span className="sr-only">{t('images.search')}</span>
          <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-app-subtle" aria-hidden />
          <Input ref={searchBox} value={q} onChange={event => { setQ(event.target.value); setPage(1) }} placeholder={t('images.search_placeholder')} className="border-app-line bg-inset pl-9" /></label>
      </div>
      {link === 'unlinked' && <p className="text-xs text-app-muted">{t('images.unlinked_hint')}</p>}

      {images.isError ? <p role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{t('images.load_failed')}</p>
      : !data ? <SkeletonList rows={5} label={t('images.loading')} />
      : empty ?? <ul aria-busy={images.isFetching || undefined} className={`divide-y divide-app-line overflow-hidden rounded-xl border border-app-line motion-safe:transition-opacity ${images.isFetching ? 'opacity-60' : ''}`}>{data.items.map(image => {
          const state = rescans[image.key]
          const pending = state === 'busy' || state === 'queued'
          return <li key={image.key} className="space-y-2 px-4 py-3">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0 space-y-0.5">
                <p className="flex min-w-0 items-center gap-2 text-sm font-medium"><Boxes className="size-4 shrink-0 text-app-muted" aria-hidden /><span className="truncate">{image.name}</span></p>
                <p className="text-xs text-app-muted">{image.reference && <span className="font-mono break-all">{image.reference}</span>}
                  {image.last_scan && <span>{image.reference ? ' · ' : ''}{t('images.last_scan', { date: formatDay(image.last_scan.created_at, { dateStyle: 'short' }) })}</span>}</p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Button size="sm" variant="outline" className="border-app-line bg-app-soft" aria-label={t('images.findings_for', { name: image.name })} onClick={() => onOpenFindings(image.key)}>{t('images.findings')}</Button>
                {image.reference && <Button size="sm" variant="ghost" disabled={pending} aria-label={state === 'queued' ? t('images.queued_for', { name: image.name }) : t('images.rescan_for', { name: image.name })}
                  onClick={() => { if (image.reference) void rescan(image.key, image.name, image.reference) }}>
                  {state === 'busy' && <LoaderCircle className="motion-safe:animate-spin" aria-hidden />}{state === 'queued' ? t('images.queued') : t('images.rescan')}</Button>}
              </div>
            </div>
            <ImageOrigin asset={image} admin={admin} onChanged={builtFrom => changed(builtFrom
              ? t('images.relinked', { image: image.name, name: builtFrom.name }) : t('images.unlinked', { image: image.name }))} />
            {typeof state === 'object' && <p role="alert" className="text-xs text-danger">{state.error}</p>}
          </li>
        })}</ul>}
      {data && <Pager page={page} perPage={PAGE_SIZE} total={data.total} onPage={setPage} loading={images.isFetching} />}
      <span role="status" className="sr-only">{announce}</span>
    </CardContent>
  </Card>
}
