import type { TFunction } from 'i18next'
import type { RegisteredImage } from '@/features/sources/add-image'

// What adding an image did: added (and queued) or already there, and the repository it was linked to by hand.
export function addedNotice(t: TFunction, image: RegisteredImage): string {
  const name = image.name
  const base = image.created ? t(image.run ? 'sources:images.added_queued' : 'sources:images.added', { name })
    : t(image.analyzed ? 'sources:images.already_analyzed' : 'sources:images.already_added', { name })
  const extra = [...(!image.created && image.run ? [t('sources:images.scan_queued')] : []),
    ...(image.built_from?.how === 'manual' ? [t('sources:images.added_built_from', { name: image.built_from.name })] : [])]
  return [base, ...extra].join(' ')
}
