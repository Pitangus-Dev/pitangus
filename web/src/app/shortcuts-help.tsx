import { useTranslation } from 'react-i18next'
import { isMac } from '@/shared/lib/shortcuts'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Keys } from '@/shared/ui/kbd'
import { visibleNavigation } from '@/app/navigation'

export function ShortcutsHelp({ open, onOpenChange, admin }: { open: boolean; onOpenChange: (open: boolean) => void; admin: boolean }) {
  const { t } = useTranslation('nav')
  const general = [
    { label: t('shortcuts.palette'), keys: [isMac() ? '⌘' : 'Ctrl', 'K'], spoken: isMac() ? t('shortcuts.spoken.command_k') : t('shortcuts.spoken.control_k') },
    { label: t('shortcuts.new_scan'), keys: ['N'], spoken: 'N' },
    { label: t('shortcuts.help'), keys: ['?'], spoken: '?' },
  ]
  const pages = visibleNavigation(admin).flatMap(group => group.items).map(item => {
    const key = item.go.toUpperCase()
    return { label: t(item.label), keys: ['G', key], spoken: t('shortcuts.spoken.then', { key }) }
  })
  const rows = (items: { label: string; keys: string[]; spoken: string }[]) => <dl className="divide-y divide-app-line border-y border-app-line">
    {items.map(item => <div key={item.label} className="flex items-center justify-between gap-4 py-1.5 text-sm">
      <dt className="text-app-secondary">{item.label}</dt>
      <dd className="flex items-center"><Keys keys={item.keys} /><span className="sr-only">{item.spoken}</span></dd>
    </div>)}
  </dl>
  return <Dialog open={open} onOpenChange={onOpenChange}>
    <DialogContent className="max-w-md">
      <DialogHeader><DialogTitle>{t('shortcuts.title')}</DialogTitle><DialogDescription>{t('shortcuts.description')}</DialogDescription></DialogHeader>
      <section aria-labelledby="shortcuts-general" className="space-y-2"><h3 id="shortcuts-general" className="text-xs text-app-subtle">{t('shortcuts.general')}</h3>{rows(general)}</section>
      <section aria-labelledby="shortcuts-pages" className="space-y-2"><h3 id="shortcuts-pages" className="text-xs text-app-subtle">{t('shortcuts.pages')}</h3>{rows(pages)}</section>
    </DialogContent>
  </Dialog>
}
