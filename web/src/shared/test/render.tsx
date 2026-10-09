import type { ReactElement } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import { ConfirmProvider } from '@/shared/ui/confirm-dialog'

// Each test gets its own query cache, without retries: a failed request shows at once.
export function renderWithQueries(element: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return { ...render(<QueryClientProvider client={client}><ConfirmProvider>{element}</ConfirmProvider></QueryClientProvider>), client }
}
