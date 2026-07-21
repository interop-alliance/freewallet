import { useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
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
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { useAuthStore } from '@/stores/authStore'
import { initialsFor, secondaryLineFor } from '@/lib/contactDisplay'
import type { StoredContact } from '@/types/contact'

export function ContactsPage() {
  const { t } = useTranslation()
  const session = useAuthStore(state => state.session)
  const [contacts, setContacts] = useState<StoredContact[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)

  useEffect(() => {
    let cancelled = false

    async function initialLoad() {
      if (!session?.storage) {
        return
      }
      try {
        const stored = await session.storage.listContacts()
        if (!cancelled) {
          setContacts(stored)
          setLoadError(false)
        }
      } catch (err) {
        console.error('Could not load contacts:', err)
        if (!cancelled) {
          setLoadError(true)
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }
    initialLoad()

    return () => {
      cancelled = true
    }
  }, [session])

  function renderContacts() {
    if (contacts.length === 0) {
      return (
        <Typography variant="body2" color="text.secondary" sx={{ mt: 3 }}>
          {t('contacts.empty')}
        </Typography>
      )
    }
    return (
      <Box sx={{ mt: 3, display: 'flex', flexWrap: 'wrap', gap: 2 }}>
        {contacts.map(({ id, contact }) => (
          <Card key={id} sx={{ width: 360, borderRadius: 3 }}>
            <CardActionArea
              component={RouterLink}
              to={`/contacts/${id}`}
              sx={{ p: 2 }}
            >
              <CardContent sx={{ p: 0, '&:last-child': { pb: 0 } }}>
                <Stack
                  direction="row"
                  spacing={2}
                  sx={{ alignItems: 'center' }}
                >
                  <Avatar sx={{ width: 56, height: 56, fontWeight: 600 }}>
                    {initialsFor(contact.displayName)}
                  </Avatar>
                  <Box sx={{ minWidth: 0 }}>
                    <Typography variant="h5" sx={{ fontWeight: 600 }} noWrap>
                      {contact.displayName}
                    </Typography>
                    {secondaryLineFor(contact) && (
                      <Typography variant="h6" color="text.secondary" noWrap>
                        {secondaryLineFor(contact)}
                      </Typography>
                    )}
                  </Box>
                </Stack>
              </CardContent>
            </CardActionArea>

            <Stack direction="row" spacing={1} sx={{ px: 2, pb: 2 }}>
              <Button
                variant="outlined"
                component={RouterLink}
                to={`/contacts/${id}/edit`}
              >
                {t('common.edit')}
              </Button>
            </Stack>
          </Card>
        ))}
      </Box>
    )
  }

  return (
    <DashboardLayout title={t('contacts.title')}>
      <Button
        variant="outlined"
        component={RouterLink}
        to="/contacts/new"
        sx={{ mt: 3, borderRadius: 2, px: 2.5, py: 1 }}
      >
        {t('contacts.addContacts')}
      </Button>

      {loadError && (
        <Alert severity="error" sx={{ mt: 2 }}>
          {t('contact.loadError')}
        </Alert>
      )}

      {loading ? <LoadingSpinner /> : renderContacts()}
    </DashboardLayout>
  )
}
