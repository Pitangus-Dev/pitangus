import type { ReactNode } from 'react'
import { ArrowSquareOutIcon } from '@phosphor-icons/react'
import { Trans, useTranslation } from 'react-i18next'
import { BRAND } from '@/shared/lib/brand'
import { Notice } from '@/shared/ui/notice'

// The public demo's account, published on purpose by the server (GET /api/auth/session); absent on any other server.
export type PublicDemo = { username: string; password: string | null }

// Shown on every view of the public demo: what this is and where the real thing is. The server enforces read-only.
export function PublicDemoNotice() {
  const { t } = useTranslation('auth')
  return <Notice tone="info">
    <Trans t={t} i18nKey="public_demo.banner" components={{ install: <RepositoryLink /> }} />
  </Notice>
}

// <Trans> fills in the link's text as children; the icon and the new-tab hint go after it.
function RepositoryLink({ children }: { children?: ReactNode }) {
  const { t } = useTranslation('auth')
  return <a href={BRAND.repo} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 underline underline-offset-2 hover:text-app-secondary">
    {children}<ArrowSquareOutIcon className="size-3" /><span className="sr-only">{t('sources:new_tab')}</span>
  </a>
}

// On the sign-in card: the published credentials, already filled in.
export function PublicDemoCredentials({ demo }: { demo: PublicDemo }) {
  const { t } = useTranslation('auth')
  return <Notice tone="info" className="text-xs">
    {demo.password
      ? <Trans t={t} i18nKey="public_demo.sign_in" values={{ username: demo.username, password: demo.password }} components={{ strong: <strong className="font-medium whitespace-nowrap" /> }} />
      : <Trans t={t} i18nKey="public_demo.sign_in_no_password" values={{ username: demo.username }} components={{ strong: <strong className="font-medium whitespace-nowrap" /> }} />}
  </Notice>
}
