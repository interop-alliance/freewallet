import { useRef } from 'react'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import Avatar from '@mui/material/Avatar'
import Link from '@mui/material/Link'
import { getIssuerDetails } from '@/lib/issuerName'
import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import { initials } from '@/lib/initials'
import { issuerInfoStyles as sx } from '@/styles/credentialStyles'

interface IssuerInfoProps {
  issuer: IVerifiableCredential['issuer']
}

export function IssuerInfo({ issuer }: IssuerInfoProps) {
  const details = getIssuerDetails(issuer)
  const imgRef = useRef<HTMLImageElement>(null)
  const hasName = !!details.name
  const avatarInitials = initials(details.name)

  return (
    <Box>
      <Typography variant="overline" sx={sx.header}>
        Issuer
      </Typography>
      <Box sx={sx.row}>
        {details.image ? (
          <Avatar
            ref={imgRef}
            src={details.image}
            alt={details.name}
            sx={sx.avatar}
            imgProps={{
              onError: () => {
                if (imgRef.current) {
                  imgRef.current.style.display = 'none'
                }
              }
            }}
          >
            {avatarInitials}
          </Avatar>
        ) : (
          <Avatar sx={sx.avatar}>{avatarInitials}</Avatar>
        )}

        <Box sx={sx.infoWrapper}>
          {hasName && (
            <Typography variant="body2" sx={sx.name}>
              {details.name}
            </Typography>
          )}

          {details.url && (
            <Link
              href={details.url}
              target="_blank"
              rel="noopener"
              variant="caption"
              sx={sx.urlLink}
            >
              {details.url}
            </Link>
          )}

        </Box>
      </Box>
    </Box>
  )
}

