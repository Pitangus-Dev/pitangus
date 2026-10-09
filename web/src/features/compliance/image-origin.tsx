import { useCallback, useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { GitBranch } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Combobox } from '@/shared/ui/combobox'
import { api } from '@/shared/api/http'
import type { PostResponse } from '@/shared/api/client'
import { evidenceAssetsQuery, keys } from '@/shared/api/queries'
import { formatDate } from '@/shared/i18n/format'

type Link = PostResponse<'/api/evidence/image-link'>
type BuiltFrom = Link['built_from']
// Any image row that knows its key and where it is built from (the evidence picker, the Images page).
type Image = { key: string; built_from?: BuiltFrom | null }

// Which repository an image is built from: its OCI label says so, or an administrator sets it by hand (a manual link
// wins). The repository brings the image into a portfolio scope and its commit shows in the reports.
export function ImageOrigin({ asset, admin, onChanged }: { asset: Image; admin: boolean; onChanged: (builtFrom: BuiltFrom) => void }) {
  const { t } = useTranslation('compliance')
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [error, setError] = useState('')
  const opener = useRef<HTMLButtonElement>(null)
  const wasEditing = useRef(false)
  // Back from the inline edit (saved or cancelled), the focus returns to the button that opened it.
  useEffect(() => { if (wasEditing.current && !editing) opener.current?.focus(); wasEditing.current = editing }, [editing])
  const built = asset.built_from
  const search = useCallback((q: string) => queryClient.fetchQuery(evidenceAssetsQuery(q, 'repository')).then(page => ({
    options: page.items.map(item => ({ id: item.key, label: item.name })), total: page.total })), [queryClient])
  const save = async (repository: string | null) => {
    setError('')
    try {
      const result = await api.post<Link>('/api/evidence/image-link', 'image-link', { image: asset.key, repository })
      onChanged(result.built_from)
      setEditing(false)
      void queryClient.invalidateQueries({ queryKey: keys.evidence })
      void queryClient.invalidateQueries({ queryKey: keys.images })
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
  }
  const origin = built ? (built.how === 'manual'
    ? t('evidence.origin.manual', { by: built.by ?? '—', date: built.at ? formatDate(built.at) : '—' })
    : built.repository ? t('evidence.origin.label') : t('evidence.origin.label_unknown')) : ''
  return <div className="space-y-2 rounded-xl border border-app-line bg-inset px-3 py-2 text-sm">
    <p className="flex flex-wrap items-center gap-x-2 gap-y-1"><GitBranch className="size-4 text-app-subtle" aria-hidden />
      {built ? <><span>{t('evidence.origin.built_from')}</span><span className="font-mono text-xs">{built.name}{built.revision ? ` @ ${built.revision.slice(0, 12)}` : ''}</span>
        <span className="text-xs text-app-muted">· {origin}</span></> : <span className="text-app-muted">{t('evidence.origin.none')}</span>}
      {admin && !editing && <Button ref={opener} size="xs" variant="ghost" onClick={() => setEditing(true)}>{built ? t('evidence.origin.change') : t('evidence.origin.link')}</Button>}
      {admin && built?.how === 'manual' && !editing && <Button size="xs" variant="ghost" onClick={() => void save(null)}>{t('evidence.origin.use_label')}</Button>}
    </p>
    {editing && <div className="flex flex-wrap items-center gap-2">
      <Combobox autoFocus className="w-full min-w-0 max-w-sm flex-1 sm:min-w-64" label={t('evidence.origin.pick_label')} placeholder={t('evidence.origin.pick')} emptyText={t('evidence.no_match')} value={null}
        search={search} onSelect={option => void save(option.id)} />
      <Button size="xs" variant="ghost" onClick={() => setEditing(false)}>{t('common:actions.cancel')}</Button></div>}
    {error && <p role="alert" className="text-xs text-danger">{error}</p>}
  </div>
}
