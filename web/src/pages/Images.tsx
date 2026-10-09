import { useState } from 'react'
import { readRoute, setRouteParam } from '@/shared/lib/route'
import { ImageList, type RepositoryFilter } from '@/features/sources/image-list'

// Images page: the repository filter travels in the URL (#/imagenes?repo=…&name=…) so the link from Repositories works.
export function Images({ admin, onOpenFindings, onNew }: { admin: boolean; onOpenFindings: (key: string) => void; onNew: () => void }) {
  const [repository, setRepository] = useState<RepositoryFilter | null>(() => {
    const params = readRoute().params
    const key = params.get('repo')
    return key ? { key, name: params.get('name') || key } : null
  })
  const clear = () => { setRepository(null); setRouteParam('repo', null); setRouteParam('name', null) }
  return <ImageList admin={admin} repository={repository} onClearRepository={clear} onOpenFindings={onOpenFindings} onNew={onNew} />
}
