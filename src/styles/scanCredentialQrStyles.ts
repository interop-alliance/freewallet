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
  },
  // The scanner's highlight overlay is positioned off the video's offsets,
  // so its wrapper is the offset parent.
  videoWrapper: {
    position: 'relative',
    width: '100%',
    display: 'flex'
  } satisfies CSSProperties,
  diagnostics: {
    m: 0,
    p: 1,
    fontSize: 11,
    fontFamily: 'monospace',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-word',
    bgcolor: 'action.hover',
    borderRadius: 1,
    maxHeight: 240,
    overflow: 'auto',
    userSelect: 'text'
  }
} as const

export const scanCredentialQrVideoStyle: CSSProperties = {
  width: '100%',
  maxHeight: 320,
  objectFit: 'cover',
  display: 'block'
}
