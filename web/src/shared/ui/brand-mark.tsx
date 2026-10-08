import { useTranslation } from 'react-i18next'
import { BRAND } from '@/shared/lib/brand'

// The approved Pitangus mark (great kiskadee head), served as is from public/assets. On light surfaces the head goes
// on its own; on the dark theme its black would merge with the background, so it sits on the cream tile (the favicon).
export function BrandMark({ size = 40, className = '', decorative = false }: { size?: number; className?: string; decorative?: boolean }) {
  const { t } = useTranslation('ui')
  const alt = decorative ? '' : t('brand_mark', { name: BRAND.name })
  return <>
    <img src="/assets/pitangus-logo.svg" width={size} height={size} alt={alt} className={`shrink-0 dark:hidden ${className}`} />
    <img src="/assets/pitangus-icon.svg" width={size} height={size} alt={alt} className={`hidden shrink-0 dark:block ${className}`} />
  </>
}

// Mark with the name: sidebar, sign-in and loading screen.
export function BrandLockup({ subtitle, size = 40 }: { subtitle?: string; size?: number }) {
  return <div className="flex items-center gap-3">
    <BrandMark size={size} decorative />
    <div className="min-w-0"><div className="text-lg leading-5 font-semibold tracking-tight text-app-fg">{BRAND.name}</div>{subtitle && <div className="text-xs text-app-subtle">{subtitle}</div>}</div>
  </div>
}
