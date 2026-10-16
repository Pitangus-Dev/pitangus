import { EngineSwitches } from '@/features/engines/engine-switches'

// Settings → Analysis engines: administrators only (the server enforces it too).
export function Engines() {
  return <EngineSwitches />
}
