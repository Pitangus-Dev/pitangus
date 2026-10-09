import { useTranslation } from 'react-i18next'
import { SelectContent, SelectGroup, SelectItem, SelectLabel } from '@/shared/ui/select'
import type { FRAMEWORKS, Region } from '@/features/findings/audit-frameworks'

// The framework list, grouped by region (Hick's law: nineteen options read faster in four labelled groups).
export function FrameworkOptions({ frameworks }: { frameworks: typeof FRAMEWORKS }) {
  const { t } = useTranslation('findings')
  const regions = [...new Set(frameworks.map(([, , , region]) => region))] as Region[]
  return <SelectContent className="border border-app-line bg-panel p-1 text-app-fg shadow-xl">{regions.map(region => <SelectGroup key={region}>
    <SelectLabel>{t(`audit.framework_groups.${region}`)}</SelectLabel>
    {frameworks.filter(([, , , other]) => other === region).map(([id, name]) => <SelectItem key={id} value={id}>{t(name)}</SelectItem>)}
  </SelectGroup>)}</SelectContent>
}
