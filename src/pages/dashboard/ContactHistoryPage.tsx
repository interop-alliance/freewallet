import { useEffect, useState } from 'react'
import Box from '@mui/material/Box'
import Chip from '@mui/material/Chip'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import type { ContactRevisionPayload } from '@interop/social-core'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { useAuthStore } from '@/stores/authStore'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { formatDateTime } from '@/lib/viewMappers/formatDate'

const ACTION_COLOR: Record<
  ContactRevisionPayload['action'],
  'success' | 'info' | 'error' | 'warning'
> = {
  create: 'success',
  update: 'info',
  delete: 'error',
  restore: 'warning'
}

export function ContactHistoryPage() {
  const { t, i18n } = useTranslation()
  const { contactId } = useParams()
  const session = useAuthStore(state => state.session)
  const [revisions, setRevisions] = useState<ContactRevisionPayload[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false

    async function load() {
      if (!session?.storage || !contactId) {
        return
      }
      try {
        // The route param is the row id; revisions are keyed by the LOGICAL
        // contact id inside the head payload (they differ for mobile-authored
        // contacts), so resolve through the stored contact first.
        const stored = await session.storage.loadContact({ id: contactId })
        if (!stored) {
          return
        }
        const items = await session.storage.listContactRevisions({
          contactId: stored.contactId
        })
        if (!cancelled) {
          setRevisions(items)
        }
      } catch (err) {
        console.error('Could not load contact history:', err)
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }
    load()

    return () => {
      cancelled = true
    }
  }, [session, contactId])

  if (!contactId) {
    return <NotFoundPage />
  }

  function renderRevisions() {
    if (revisions.length === 0) {
      return (
        <Typography variant="body2" color="text.secondary" sx={{ mt: 3 }}>
          {t('contactHistory.empty')}
        </Typography>
      )
    }
    return (
      <Stack spacing={1.5} sx={{ mt: 3, maxWidth: 560 }}>
        {revisions.map((revision, index) => (
          <Box
            key={`${revision.timestamp}-${index}`}
            sx={{
              p: 2,
              borderRadius: 2,
              border: '1px solid',
              borderColor: 'divider'
            }}
          >
            <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
              <Chip
                size="small"
                label={t(`contactHistory.actions.${revision.action}`)}
                color={ACTION_COLOR[revision.action]}
              />
              <Typography variant="body2" color="text.secondary">
                {formatDateTime(new Date(revision.timestamp), i18n.language)}
              </Typography>
            </Stack>
            <Typography variant="body1" sx={{ mt: 1 }}>
              {revision.snapshot.displayName}
            </Typography>
          </Box>
        ))}
      </Stack>
    )
  }

  return (
    <DashboardLayout title={t('contactHistory.title')}>
      {loading ? <LoadingSpinner /> : renderRevisions()}
    </DashboardLayout>
  )
}
