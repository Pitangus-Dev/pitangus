import { BugIcon, EngineIcon, GitPullRequestIcon, GlobeIcon, ListMagnifyingGlassIcon, PackageIcon, PlugsConnectedIcon, ScalesIcon, ScrollIcon, ShieldIcon, ShieldWarningIcon, SquaresFourIcon, StackIcon, TargetIcon, TreeStructureIcon, UsersIcon } from '@phosphor-icons/react'

export type View = 'overview' | 'analyses' | 'new' | 'findings' | 'coverage' | 'repositories' | 'images' | 'domains' | 'domain' | 'integrations' | 'account' | 'users' | 'pulls' | 'threats' | 'cves' | 'compliance' | 'policies' | 'engines'
// `go` is the letter after G that opens the page (G then O, the overview). Letters stay the same in every language.
export type NavItem = { id: View; label: string; icon: typeof ShieldIcon; go: string; admin?: boolean }

// Hick's law: three named groups instead of a dozen options in a row.
export const navigation: { id: string; label: string; items: NavItem[] }[] = [
  { id: 'risk', label: 'groups.risk', items: [
    { id: 'overview', label: 'items.overview', icon: SquaresFourIcon, go: 'o' },
    { id: 'findings', label: 'items.findings', icon: ShieldWarningIcon, go: 'f' },
    { id: 'threats', label: 'items.threats', icon: TreeStructureIcon, go: 't' },
    { id: 'coverage', label: 'items.coverage', icon: TargetIcon, go: 'v' },
    { id: 'cves', label: 'items.cves', icon: BugIcon, go: 'c' },
    { id: 'compliance', label: 'items.compliance', icon: ScalesIcon, go: 'm' },
  ] },
  { id: 'scanning', label: 'groups.scanning', items: [
    { id: 'analyses', label: 'items.analyses', icon: ListMagnifyingGlassIcon, go: 'a' },
    { id: 'repositories', label: 'items.repositories', icon: StackIcon, go: 'r' },
    { id: 'images', label: 'items.images', icon: PackageIcon, go: 'i' },
    { id: 'domains', label: 'items.domains', icon: GlobeIcon, go: 'd' },
    { id: 'pulls', label: 'items.pulls', icon: GitPullRequestIcon, go: 'p' },
  ] },
  { id: 'settings', label: 'groups.settings', items: [
    { id: 'policies', label: 'items.policies', icon: ScrollIcon, go: 'l' },
    { id: 'integrations', label: 'items.integrations', icon: PlugsConnectedIcon, go: 'e' },
    // Analysis engines and Users are for administrators only; the server enforces it too.
    { id: 'engines', label: 'items.engines', icon: EngineIcon, go: 'n', admin: true },
    { id: 'users', label: 'items.users', icon: UsersIcon, go: 'u', admin: true },
  ] },
]

export const visibleNavigation = (admin: boolean) =>
  navigation.map(group => ({ ...group, items: group.items.filter(item => !item.admin || admin) }))
