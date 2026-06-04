import Avatar from '@mui/material/Avatar'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { DashboardLayout } from '@/components/DashboardLayout'
import { getContacts } from '@/lib/getContacts'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { contactDetailStyles } from '@/styles/appStyles'

export function ContactDetailPage() {
  const { t } = useTranslation()
  const { contactId } = useParams()
  const contact = getContacts().find(item => item.id === contactId)

  if (!contactId || !contact) {
    return <NotFoundPage />
  }

  return (
    <DashboardLayout title={t('contactDetail.title')}>
      <Card sx={contactDetailStyles.card}>
        <CardContent sx={contactDetailStyles.cardContent}>
          <Stack direction="row" spacing={2} sx={contactDetailStyles.headerRow}>
            <Avatar sx={contactDetailStyles.avatar}>{contact.logo}</Avatar>
            <Box>
              <Typography variant="h4" sx={contactDetailStyles.name}>
                {contact.displayName}
              </Typography>
              <Typography variant="h6" color="text.secondary">
                {contact.contactType}
              </Typography>
            </Box>
          </Stack>

          <Stack direction="row" spacing={1.5} sx={contactDetailStyles.actions}>
            <Button
              variant="outlined"
              disabled
              sx={contactDetailStyles.actionButton}
            >
              {t('common.edit')}
            </Button>
            <Button
              variant="outlined"
              disabled
              sx={contactDetailStyles.actionButton}
            >
              {t('common.message')}
            </Button>
          </Stack>
        </CardContent>
      </Card>
    </DashboardLayout>
  )
}
