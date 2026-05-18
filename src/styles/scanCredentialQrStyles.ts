import type { CSSProperties } from 'react'

export const scanCredentialQrStyles = {
  previewContainer: {
    position: 'relative',
    borderRadius: 2,
    overflow: 'hidden',
    bgcolor: 'common.black',
    minHeight: 220,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center'
  }
} as const

export const scanCredentialQrVideoStyle: CSSProperties = {
  width: '100%',
  maxHeight: 320,
  objectFit: 'cover',
  display: 'block'
}
