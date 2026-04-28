import Avatar from '@mui/material/Avatar'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useParams } from 'react-router'
import { DashboardLayout } from '@/components/DashboardLayout'
import { getContacts } from '@/lib/getContacts'
import { NotFoundPage } from '@/pages/NotFoundPage'

export function ContactDetailPage() {
  const { contactId } = useParams()
  const contact = getContacts().find(item => item.id === contactId)

  if (!contactId || !contact) {
    return <NotFoundPage />
  }

  return (
    <DashboardLayout title="Contact Details">
      <Card sx={{ mt: 3, maxWidth: 560, borderRadius: 3 }}>
        <CardContent sx={{ p: 3 }}>
          <Stack direction="row" spacing={2} sx={{ alignItems: 'center' }}>
            <Avatar sx={{ width: 64, height: 64, fontSize: '1.25rem', fontWeight: 600 }}>
              {contact.logo}
            </Avatar>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 600 }}>
                {contact.displayName}
              </Typography>
              <Typography variant="h6" color="text.secondary">
                {contact.contactType}
              </Typography>
            </Box>
          </Stack>

          <Stack direction="row" spacing={1.5} sx={{ mt: 3 }}>
            <Button variant="outlined" disabled sx={{ textTransform: 'none' }}>
              Edit
            </Button>
            <Button variant="outlined" disabled sx={{ textTransform: 'none' }}>
              Message
            </Button>
          </Stack>
        </CardContent>
      </Card>
    </DashboardLayout>
  )
}
