import { useCallback, useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
import Avatar from '@mui/material/Avatar'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardActionArea from '@mui/material/CardActionArea'
import CardContent from '@mui/material/CardContent'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { MdSync } from 'react-icons/md'
import { Link as RouterLink } from 'react-router'
import { useTranslation } from 'react-i18next'
import type { FuseOptionKey } from 'fuse.js'
import {
  compareContactsByName,
  getDids,
  initialsFor,
  secondaryLineFor
} from '@interop/social-core'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { SearchField } from '@/components/SearchField'
import { useAuthStore } from '@/stores/authStore'
import { syncController } from '@/stores/syncController'
import { useSearch } from '@/hooks/useSearch'
import { flattenSearchValues } from '@/lib/searchValues'
import { dashboardStyles } from '@/styles/appStyles'
import type { StoredContact } from '@/types/contact'

// Plumbing fields a person would never search for -- record identifiers, the
// starred flag (which would otherwise be indexed as the words 'true'/'false'),
// and the per-entry label strings ('home', 'work', ...) -- are excluded, so
// they cannot fuzzy-match a real query.
const CONTACT_NON_SEARCHABLE_FIELDS = ['id', 'nativeId', 'isStarred', 'label']

// Declared outside the component so this array is the same object on every
// render; useSearch's index is memoized on it, so a fresh array each render
// would rebuild the index on every keystroke. The one `getFn` key pulls out
// every value in the contact instead of naming fields one by one, so search
// covers the whole contact, not just a few chosen fields; `getDids` adds the
// contact's DIDs in their unmangled form, since a DID is stored as an
// `http(s)://did:` url entry that a pasted `did:key:...` would not match.
const CONTACT_SEARCH_KEYS: FuseOptionKey<StoredContact>[] = [
  {
    name: 'contactFields',
    getFn: item => [
      ...flattenSearchValues({
        root: item.contact,
        excludeKeys: CONTACT_NON_SEARCHABLE_FIELDS
      }),
      ...getDids(item.contact)
    ]
  }
]

export function ContactsPage() {
  const { t } = useTranslation()
  const session = useAuthStore(state => state.session)
  const [contacts, setContacts] = useState<StoredContact[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const [syncing, setSyncing] = useState(false)

  const {
    query,
    setQuery,
    results: searchedContacts
  } = useSearch({ items: contacts, keys: CONTACT_SEARCH_KEYS })

  // `isStale` lets the mount effect drop a read whose effect was cleaned up;
  // the imperative refreshes never cancel and pass nothing.
  const loadContacts = useCallback(
    async (isStale?: () => boolean) => {
      if (!session?.storage) {
        return
      }
      const stored = await session.storage.listContacts()
      if (isStale?.()) {
        return
      }
      // The shared list order, so the same account lists identically on
      // every replica.
      setContacts(
        [...stored].sort((left, right) =>
          compareContactsByName(left.contact, right.contact)
        )
      )
      setLoadError(false)
    },
    [session]
  )

  useEffect(() => {
    let cancelled = false

    async function initialLoad() {
      if (!session?.storage) {
        return
      }
      try {
        await loadContacts(() => cancelled)
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
  }, [session, loadContacts])

  async function handleSync() {
    setSyncing(true)
    try {
      // Kick an immediate replication cycle (no-op for guests / no remote);
      // pulled changes land in the local replica in the background.
      syncController.reSync()
      await loadContacts()
    } catch (err) {
      console.error('Could not refresh contacts:', err)
      setLoadError(true)
    } finally {
      // Always release the Sync button, even on a failed refresh.
      setSyncing(false)
    }
  }

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

        <Button
          variant="outlined"
          size="small"
          onClick={handleSync}
          disabled={syncing}
          startIcon={
            <MdSync size={16} style={dashboardStyles.syncIcon(syncing)} />
          }
          sx={dashboardStyles.syncButton}
        >
          {t('common.sync')}
        </Button>

        {!loading && contacts.length > 0 && (
          <SearchField
            value={query}
            onChange={setQuery}
            placeholder={t('contacts.searchPlaceholder')}
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
