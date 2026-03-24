import Box from '@mui/material/Box'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Typography from '@mui/material/Typography'
import { BsAward } from 'react-icons/bs'
import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import { credentialTitle } from '@/lib/credentialTitle'
import { credentialCardStyles } from '@/styles/appStyles'

interface CredentialCardProps {
  credential: IVerifiableCredential
}

export function CredentialCard({ credential }: CredentialCardProps) {
  const description =
    'description' in credential.credentialSubject
      ? credential.credentialSubject.description
      : 'No Description'
  return (
    <Card variant="outlined" sx={credentialCardStyles.card}>
      <CardContent sx={credentialCardStyles.cardContent}>
        <Typography
          variant="subtitle1"
          gutterBottom
          sx={credentialCardStyles.title}
        >
          {credentialTitle(credential)}
        </Typography>
        <Typography
          variant="body2"
          color="text.secondary"
          sx={credentialCardStyles.description}
        >
          {description}
        </Typography>
        <Box sx={credentialCardStyles.badge}>
          <BsAward size={28} />
        </Box>
      </CardContent>
    </Card>
  )
}
