import { useCallback, useRef, useState, type ReactNode } from "react"
import { useTranslation } from "react-i18next"

import { Button } from "@/shared/ui/button"
import { ConfirmContext, type Confirm, type ConfirmOptions } from "@/shared/ui/confirm"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/shared/ui/dialog"

// One confirmation at a time for the whole panel; asking again settles the previous one as "no".
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const [request, setRequest] = useState<ConfirmOptions | null>(null)
  const [open, setOpen] = useState(false)
  const pending = useRef<((ok: boolean) => void) | null>(null)
  const cancel = useRef<HTMLButtonElement>(null)

  const confirm = useCallback<Confirm>(options => new Promise<boolean>(resolve => {
    pending.current?.(false)
    pending.current = resolve
    setRequest(options)
    setOpen(true)
  }), [])

  const settle = (ok: boolean) => {
    pending.current?.(ok)
    pending.current = null
    setOpen(false)
  }

  return <ConfirmContext.Provider value={confirm}>
    {children}
    <Dialog open={open} onOpenChange={next => { if (!next) settle(false) }}>
      {request && <DialogContent role="alertdialog" initialFocus={cancel} showCloseButton={false} className="max-w-md">
        <DialogHeader className="pr-0"><DialogTitle>{request.title}</DialogTitle>
          {request.description && <DialogDescription>{request.description}</DialogDescription>}</DialogHeader>
        <DialogFooter>
          <Button ref={cancel} variant="ghost" onClick={() => settle(false)}>{request.cancelLabel ?? t("common:actions.cancel")}</Button>
          <Button className={request.destructive ? "bg-danger-solid text-on-solid hover:bg-danger-solid/90" : undefined} onClick={() => settle(true)}>{request.confirmLabel}</Button>
        </DialogFooter>
      </DialogContent>}
    </Dialog>
  </ConfirmContext.Provider>
}
