import { createContext, useContext, type ReactNode } from "react"

export type ConfirmOptions = {
  title: string
  description?: ReactNode
  confirmLabel: string
  cancelLabel?: string
  destructive?: boolean
}

export type Confirm = (options: ConfirmOptions) => Promise<boolean>

export const ConfirmContext = createContext<Confirm | null>(null)

// Asks in an in-app dialog (mounted by ConfirmProvider) instead of the browser one.
export function useConfirm(): Confirm {
  const confirm = useContext(ConfirmContext)
  if (!confirm) throw new Error("useConfirm needs a ConfirmProvider")
  return confirm
}
