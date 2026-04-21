import { useContext } from 'react'
import { InfoBox, type InfoBoxValue } from '@/context/infoBoxStore'

export function useInfoBox(): InfoBoxValue {
  const ctx = useContext(InfoBox)
  if (!ctx) {
    throw new Error('useInfoBox must be used within <InfoBoxProvider>')
  }
  return ctx
}
