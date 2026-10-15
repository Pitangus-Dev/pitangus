import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { CheckIcon, XIcon } from '@phosphor-icons/react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/shared/ui/button'
import { Card, CardContent } from '@/shared/ui/card'
import { onboardingQuery } from '@/shared/api/queries'

type Step = { id: string; done: boolean; title: string; hint: string; view?: string; action?: string }
const HIDDEN = 'pitangus-getting-started-hidden'

// First steps: each one is what the server sees (GET /api/onboarding), wherever it was done; nothing is ticked by
// clicking here. One action per step. They hide on their own once done, or when the person dismisses them (only in
// this browser).
export function GettingStarted({ onNavigate }: { onNavigate: (view: string) => void }) {
  const { t } = useTranslation('onboarding')
  const [hidden, setHidden] = useState(() => { try { return localStorage.getItem(HIDDEN) === '1' } catch { return false } })
  const state = useQuery({ ...onboardingQuery(), enabled: !hidden }).data
  if (hidden || !state) return null
  const admin = state.admin
  const steps: Step[] = [
    { id: 'mfa', done: state.mfa, title: t('steps.mfa.title'), hint: t('steps.mfa.hint'), view: 'account', action: t('steps.mfa.action') },
    { id: 'github', done: state.github, title: t('steps.github.title'), hint: admin ? t('steps.github.hint_admin') : t('steps.github.hint_member'), view: admin ? 'integrations' : undefined, action: t('steps.github.action') },
    { id: 'analyzed', done: state.analyzed, title: t('steps.analyzed.title'), hint: state.demo ? t('steps.analyzed.hint_demo')
      : admin ? t('steps.analyzed.hint_admin') : t('steps.analyzed.hint_member'), view: 'new', action: t('steps.analyzed.action') },
    { id: 'watching', done: state.watching, title: t('steps.watching.title'), hint: admin ? t('steps.watching.hint_admin') : t('steps.watching.hint_member'), view: admin ? 'pulls' : undefined, action: t('steps.watching.action') },
    { id: 'alerts', done: state.alerts, title: t('steps.alerts.title'), hint: admin ? t('steps.alerts.hint_admin') : t('steps.alerts.hint_member'), view: admin ? 'integrations' : undefined, action: t('steps.alerts.action') },
  ]
  const pending = steps.filter(step => !step.done)
  if (!pending.length) return null
  const next = pending.find(step => step.view)  // one primary action: the first step this person can take
  const dismiss = () => { try { localStorage.setItem(HIDDEN, '1') } catch { /* no storage: hidden until reload */ } setHidden(true) }
  return <Card className="border-brand/30 bg-panel"><CardContent className="space-y-3 p-5">
    <div className="flex items-start justify-between gap-3">
      <div><h2 className="text-base font-semibold">{t('title')}</h2><p className="text-sm text-app-muted">{t('progress', { done: steps.length - pending.length, total: steps.length })}</p></div>
      <Button variant="ghost" size="icon-sm" aria-label={t('hide')} onClick={dismiss}><XIcon /></Button>
    </div>
    <ol className="divide-y divide-app-line rounded-xl border border-app-line">{steps.map(step => <li key={step.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
      <span className="flex min-w-0 items-start gap-3">
        <span aria-hidden className={`mt-0.5 grid size-5 shrink-0 place-items-center rounded-full border ${step.done ? 'border-success bg-success-soft text-success' : 'border-app-line'}`}>{step.done && <CheckIcon className="size-3" />}</span>
        <span className="min-w-0"><span className={`block text-sm font-medium ${step.done ? 'text-app-subtle line-through' : ''}`}>{step.title}<span className="sr-only"> {step.done ? t('done') : t('pending')}</span></span>
          {!step.done && <span className="block text-xs text-app-muted">{step.hint}</span>}</span>
      </span>
      {!step.done && step.view && (step.id === next?.id
        ? <Button size="sm" onClick={() => onNavigate(step.view!)}>{step.action}</Button>
        : <Button size="sm" variant="ghost" onClick={() => onNavigate(step.view!)} className="text-app-muted">{step.action}</Button>)}
    </li>)}</ol>
  </CardContent></Card>
}
