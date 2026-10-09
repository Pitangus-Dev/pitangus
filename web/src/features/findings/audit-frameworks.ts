import { useQuery } from '@tanstack/react-query'
import { craPolicyQuery } from '@/shared/api/queries'

// Audit evidence frameworks, shared by the audit report dialog (Findings) and the evidence hub (Compliance).
export type Framework = 'soc2' | 'iso27001' | 'pci' | 'cra' | 'br-cmn' | 'cl-21663' | 'co-sfc' | 'nis2' | 'dora' | 'gdpr' | 'nist-ssdf' | 'nist-csf' | 'nist-800-53' | 'hipaa' | 'mx-cnbv-cub' | 'mx-cnbv-ifc' | 'mx-ifpe' | 'mx-lfpdppp' | 'general'

export type Region = 'international' | 'eu' | 'us' | 'latam'
// [id, name key, hint key, region]; contiguous by region, the order the selector groups them in.
export const FRAMEWORKS: [Framework, string, string, Region][] = [
  ['soc2', 'audit.frameworks.soc2.name', 'audit.frameworks.soc2.hint', 'international'],
  ['iso27001', 'audit.frameworks.iso27001.name', 'audit.frameworks.iso27001.hint', 'international'],
  ['pci', 'audit.frameworks.pci.name', 'audit.frameworks.pci.hint', 'international'],
  ['general', 'audit.frameworks.general.name', 'audit.frameworks.general.hint', 'international'],
  ['cra', 'audit.frameworks.cra.name', 'audit.frameworks.cra.hint', 'eu'],
  ['nis2', 'audit.frameworks.nis2.name', 'audit.frameworks.nis2.hint', 'eu'],
  ['dora', 'audit.frameworks.dora.name', 'audit.frameworks.dora.hint', 'eu'],
  ['gdpr', 'audit.frameworks.gdpr.name', 'audit.frameworks.gdpr.hint', 'eu'],
  ['nist-ssdf', 'audit.frameworks.nist_ssdf.name', 'audit.frameworks.nist_ssdf.hint', 'us'],
  ['nist-csf', 'audit.frameworks.nist_csf.name', 'audit.frameworks.nist_csf.hint', 'us'],
  ['nist-800-53', 'audit.frameworks.nist_800_53.name', 'audit.frameworks.nist_800_53.hint', 'us'],
  ['hipaa', 'audit.frameworks.hipaa.name', 'audit.frameworks.hipaa.hint', 'us'],
  ['br-cmn', 'audit.frameworks.br_cmn.name', 'audit.frameworks.br_cmn.hint', 'latam'],
  ['cl-21663', 'audit.frameworks.cl_21663.name', 'audit.frameworks.cl_21663.hint', 'latam'],
  ['co-sfc', 'audit.frameworks.co_sfc.name', 'audit.frameworks.co_sfc.hint', 'latam'],
  ['mx-cnbv-cub', 'audit.frameworks.mx_cnbv_cub.name', 'audit.frameworks.mx_cnbv_cub.hint', 'latam'],
  ['mx-cnbv-ifc', 'audit.frameworks.mx_cnbv_ifc.name', 'audit.frameworks.mx_cnbv_ifc.hint', 'latam'],
  ['mx-ifpe', 'audit.frameworks.mx_ifpe.name', 'audit.frameworks.mx_ifpe.hint', 'latam'],
  ['mx-lfpdppp', 'audit.frameworks.mx_lfpdppp.name', 'audit.frameworks.mx_lfpdppp.hint', 'latam'],
]
const MEMORY = 'pitangus-audit-report'
// What doesn't change between reports is remembered in this browser (a convenience; nothing leaves it).
export const remembered = (): Partial<Record<string, string>> => { try { return JSON.parse(localStorage.getItem(MEMORY) ?? '{}') } catch { return {} } }
export const rememberedFramework = () => remembered().framework as Framework | undefined
export const rememberFramework = (framework: Framework) => { try { localStorage.setItem(MEMORY, JSON.stringify({ ...remembered(), framework })) } catch { /* no storage */ } }
// The CRA mapping only shows when the workspace sells products in the EU (policy in Policies).
export function useAuditFrameworks() {
  const policy = useQuery(craPolicyQuery())
  // While the policy loads nothing is hidden, so a remembered CRA choice isn't swapped for another framework.
  return policy.isPending ? FRAMEWORKS : FRAMEWORKS.filter(([id]) => id !== 'cra' || policy.data?.enabled === true)
}
export const rememberFrameworkDetails = (details: Record<string, string>) => { try { localStorage.setItem(MEMORY, JSON.stringify(details)) } catch { /* no storage */ } }
