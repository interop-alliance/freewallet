import Box from '@mui/material/Box'
import Card from '@mui/material/Card'
import CardActionArea from '@mui/material/CardActionArea'
import CardContent from '@mui/material/CardContent'
import Typography from '@mui/material/Typography'
import { Link as RouterLink } from 'react-router'
import { BsAward } from 'react-icons/bs'
import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import { getDisplayFields } from '@/lib/viewMappers/credentialDisplayFields'
import { credentialTitle } from '@/lib/viewMappers/credentialTitle'
import { credentialCardStyles } from '@/styles/appStyles'
import { useVerification } from '@/hooks/useVerification'
import { VerificationStatusBadge } from '@/components/credentialDetails/VerificationPanel'

interface CredentialCardProps {
  cid: string
  credential: IVerifiableCredential
}

export function CredentialCard({ cid, credential }: CredentialCardProps) {
  const { credentialDescription } = getDisplayFields(credential)
  const description = credentialDescription ?? 'No Description'
  const { result, loading, error } = useVerification(credential)

  return (
    <Card variant="outlined">
      <CardActionArea
        sx={credentialCardStyles.card}
        component={RouterLink}
        to={`/credential/${cid}`}
      >
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
          <Box sx={{ mt: 1.5 }}>
            <VerificationStatusBadge
              result={result}
              loading={loading}
              error={error}
            />
          </Box>
          <Box sx={credentialCardStyles.badge}>
            <BsAward size={28} />
          </Box>
        </CardContent>
      </CardActionArea>
    </Card>
  )
}
