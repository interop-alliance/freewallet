import { useState } from 'react'
import Avatar from '@mui/material/Avatar'
import type { SxProps, Theme } from '@mui/material/styles'

const UNKNOWN_LOGO = '?'

interface IssuerAvatarProps {
  src?: string
  alt?: string
  sx?: SxProps<Theme>
}

export function IssuerAvatar({ src, alt, sx }: IssuerAvatarProps) {
  const [imageFailed, setImageFailed] = useState(false)
  const showImage = !!src && !imageFailed

  return (
    <Avatar
      variant="square"
      src={showImage ? src : undefined}
      alt={alt}
      sx={sx}
      slotProps={
        showImage
          ? {
              img: {
                onError: () => {
                  setImageFailed(true)
                }
              }
            }
          : undefined
      }
    >
      {UNKNOWN_LOGO}
    </Avatar>
  )
}
