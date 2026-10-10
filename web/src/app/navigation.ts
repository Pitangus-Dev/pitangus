import {
  Boxes, Bug, GitPullRequest, Globe2, Landmark, Layers3, LayoutDashboard, Network, PlugZap, Radar, ScrollText, SearchCheck, Shield, ShieldAlert, UsersRound,
} from 'lucide-react'

export type View = 'overview' | 'analyses' | 'new' | 'findings' | 'coverage' | 'repositories' | 'images' | 'domains' | 'domain' | 'integrations' | 'account' | 'users' | 'pulls' | 'threats' | 'cves' | 'compliance' | 'policies'
// `go` is the letter after G that opens the page (G then O, the overview). Letters stay the same in every language.
export type NavItem = { id: View; label: string; icon: typeof Shield; go: string; admin?: boolean }

// Hick's law: three named groups instead of a dozen options in a row.
export const navigation: { id: string; label: string; items: NavItem[] }[] = [
  { id: 'risk', label: 'groups.risk', items: [
    { id: 'overview', label: 'items.overview', icon: LayoutDashboard, go: 'o' },
    { id: 'findings', label: 'items.findings', icon: ShieldAlert, go: 'f' },
    { id: 'threats', label: 'items.threats', icon: Network, go: 't' },
    { id: 'coverage', label: 'items.coverage', icon: Radar, go: 'v' },
    { id: 'cves', label: 'items.cves', icon: Bug, go: 'c' },
    { id: 'compliance', label: 'items.compliance', icon: Landmark, go: 'm' },
  ] },
  { id: 'scanning', label: 'groups.scanning', items: [
    { id: 'analyses', label: 'items.analyses', icon: SearchCheck, go: 'a' },
    { id: 'repositories', label: 'items.repositories', icon: Layers3, go: 'r' },
    { id: 'images', label: 'items.images', icon: Boxes, go: 'i' },
    { id: 'domains', label: 'items.domains', icon: Globe2, go: 'd' },
    { id: 'pulls', label: 'items.pulls', icon: GitPullRequest, go: 'p' },
  ] },
  { id: 'settings', label: 'groups.settings', items: [
    { id: 'policies', label: 'items.policies', icon: ScrollText, go: 'l' },
    { id: 'integrations', label: 'items.integrations', icon: PlugZap, go: 'e' },
    // Users is for administrators only; the server enforces it too.
    { id: 'users', label: 'items.users', icon: UsersRound, go: 'u', admin: true },
  ] },
]

export const visibleNavigation = (admin: boolean) =>
  navigation.map(group => ({ ...group, items: group.items.filter(item => !item.admin || admin) }))
