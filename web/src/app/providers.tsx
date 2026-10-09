import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { ApiError } from '@/shared/api/http'
import i18n from '@/shared/i18n'
import { ConfirmProvider } from '@/shared/ui/confirm-dialog'

// Estado del servidor con TanStack Query: caché compartida entre vistas, reintentos acotados y sondeo solo mientras
// haga falta (refetchInterval). Un 4xx no se reintenta: es una respuesta, no un fallo de red.
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      retry: (count, error) => !(error instanceof ApiError && error.status >= 400 && error.status < 500) && count < 2,
      refetchOnWindowFocus: true,
    },
  },
})

// Server-rendered text depends on the language: refetch it when the reader switches.
i18n.on('languageChanged', () => { void queryClient.invalidateQueries() })

export function Providers({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={queryClient}><ConfirmProvider>{children}</ConfirmProvider></QueryClientProvider>
}
