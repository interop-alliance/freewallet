import { useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
import Avatar from '@mui/material/Avatar'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardActionArea from '@mui/material/CardActionArea'
import CardContent from '@mui/material/CardContent'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { Link as RouterLink } from 'react-router'
import { useTranslation } from 'react-i18next'
import type { FuseOptionKey } from 'fuse.js'
import {
  compareContactsByName,
  initialsFor,
  secondaryLineFor
} from '@interop/social-core'
import { MdSearch } from 'react-icons/md'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { useAuthStore } from '@/stores/authStore'
import { useSearch } from '@/hooks/useSearch'
import { flattenSearchValues } from '@/lib/searchValues'
import { historyStyles } from '@/styles/appStyles'
import type { StoredContact } from '@/types/contact'

// Declared outside the component so this array is the same object on every
// render; useSearch's index is memoized on it, so a fresh array each render
// would rebuild the index on every keystroke. The one `getFn` key pulls out
// every value in the contact instead of naming fields one by one, so search
// covers the whole contact, not just a few chosen fields.
const CONTACT_SEARCH_KEYS: FuseOptionKey<StoredContact>[] = [
  { name: 'contactFields', getFn: item => flattenSearchValues(item.contact) }
]

export function ContactsPage() {
  const { t } = useTranslation()
  const session = useAuthStore(state => state.session)
  const [contacts, setContacts] = useState<StoredContact[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)

  const {
    query,
    setQuery,
    results: searchedContacts
  } = useSearch({ items: contacts, keys: CONTACT_SEARCH_KEYS })

  useEffect(() => {
    let cancelled = false

    async function initialLoad() {
      if (!session?.storage) {
        return
      }
      try {
        const stored = await session.storage.listContacts()
        if (!cancelled) {
          // The shared list order, so the same account lists identically on
          // every replica.
          setContacts(
            [...stored].sort((left, right) =>
              compareContactsByName(left.contact, right.contact)
            )
          )
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
    if (searchedContacts.length === 0) {
      return (
        <Typography variant="body2" color="text.secondary" sx={{ mt: 3 }}>
          {t('contacts.noResults')}
        </Typography>
      )
    }
    return (
      <Box sx={{ mt: 3, display: 'flex', flexWrap: 'wrap', gap: 2 }}>
        {searchedContacts.map(({ id, contact }) => (
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
      <Stack
        direction="row"
        spacing={2}
        sx={{ mt: 3, flexWrap: 'wrap', alignItems: 'center' }}
      >
        <Button
          variant="outlined"
          component={RouterLink}
          to="/contacts/new"
          sx={{ borderRadius: 2, px: 2.5, py: 1 }}
        >
          {t('contacts.addContacts')}
        </Button>

        {!loading && contacts.length > 0 && (
          <TextField
            size="small"
            value={query}
            onChange={event => setQuery(event.target.value)}
            placeholder={t('contacts.searchPlaceholder')}
            sx={historyStyles.searchField}
            slotProps={{
              input: {
                startAdornment: (
                  <Box
                    component="span"
                    sx={{ display: 'flex', color: 'text.secondary', mr: 1 }}
                  >
                    <MdSearch />
                  </Box>
                )
              }
            }}
          />
        )}
      </Stack>

      {loadError && (
        <Alert severity="error" sx={{ mt: 2 }}>
          {t('contact.loadError')}
        </Alert>
      )}

      {loading ? <LoadingSpinner /> : renderContacts()}
    </DashboardLayout>
  )
}
