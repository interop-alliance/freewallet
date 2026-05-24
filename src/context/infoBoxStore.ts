import { createContext } from 'react'

export interface InfoBoxOptions {
  /**
   * Doc slug matching a file under public/docs/, e.g. 'vcs', 'dids', 'keys'
   */
  docUrl: string
  /**
   * Optional heading shown at the top of the lightbox
   */
  title?: string
}

export interface InfoBoxValue {
  displayInfoBox: (options: InfoBoxOptions) => void
}

export const InfoBox = createContext<InfoBoxValue | null>(null)
