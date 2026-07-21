import Avatar from '@mui/material/Avatar'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardActionArea from '@mui/material/CardActionArea'
import CardContent from '@mui/material/CardContent'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { Link as RouterLink } from 'react-router'
import { useTranslation } from 'react-i18next'
import { DashboardLayout } from '@/components/DashboardLayout'
import { getContacts } from '@/lib/getContacts'

export function ContactsPage() {
  const { t } = useTranslation()
  const contacts = getContacts()

  return (
    <DashboardLayout title={t('contacts.title')}>
      <Button
        variant="outlined"
        disabled
        sx={{ mt: 3, borderRadius: 2, px: 2.5, py: 1 }}
      >
        {t('contacts.addContacts')}
      </Button>

      <Box sx={{ mt: 3, display: 'flex', flexWrap: 'wrap', gap: 2 }}>
        {contacts.map(contact => (
          <Card key={contact.id} sx={{ width: 360, borderRadius: 3 }}>
            <CardActionArea
              component={RouterLink}
              to={`/contacts/${contact.id}`}
              sx={{ p: 2 }}
            >
              <CardContent sx={{ p: 0, '&:last-child': { pb: 0 } }}>
                <Stack
                  direction="row"
                  spacing={2}
                  sx={{ alignItems: 'center' }}
                >
                  <Avatar sx={{ width: 56, height: 56, fontWeight: 600 }}>
                    {contact.logo}
                  </Avatar>
                  <Box>
                    <Typography variant="h5" sx={{ fontWeight: 600 }}>
                      {contact.displayName}
                    </Typography>
                    <Typography variant="h6" color="text.secondary">
                      {contact.contactType}
                    </Typography>
                  </Box>
                </Stack>
              </CardContent>
            </CardActionArea>

            <Stack direction="row" spacing={1} sx={{ px: 2, pb: 2 }}>
              <Button variant="outlined" disabled>
                {t('common.edit')}
              </Button>
              <Button variant="outlined" disabled>
                {t('common.message')}
              </Button>
            </Stack>
          </Card>
        ))}
      </Box>
    </DashboardLayout>
  )
}
