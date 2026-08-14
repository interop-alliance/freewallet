import { useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import ButtonBase from '@mui/material/ButtonBase'
import Chip from '@mui/material/Chip'
import Collapse from '@mui/material/Collapse'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { Link as RouterLink, useNavigate, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { MdArrowBack } from 'react-icons/md'
import {
  getDids,
  snapshotLines,
  type ContactRevisionPayload
} from '@interop/social-core'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { useAuthStore } from '@/stores/authStore'
import { showToast } from '@/stores/toastStore'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { formatDateTime } from '@/lib/viewMappers/formatDate'
import { storageStyles } from '@/styles/appStyles'

const ACTION_COLOR: Record<
  ContactRevisionPayload['action'],
  'success' | 'info' | 'error' | 'warning'
> = {
  create: 'success',
  update: 'info',
  delete: 'error',
  restore: 'warning'
}

/**
 * How much of a revision's `writerId` the attribution line shows -- enough to
 * tell two writing agents apart, and the same prefix length the mobile wallet
 * displays.
 */
const WRITER_ID_PREFIX_LENGTH = 8

export function ContactHistoryPage() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const { contactId } = useParams()
  const session = useAuthStore(state => state.session)
  const [revisions, setRevisions] = useState<ContactRevisionPayload[]>([])
  const [loading, setLoading] = useState(true)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [restoring, setRestoring] = useState(false)
  const [restoreError, setRestoreError] = useState(false)

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

  /**
   * Rewrites the contact with this revision's snapshot, appending a `restore`
   * revision of its own. The id passed is the ROUTE param -- the row id
   * `updateContact` addresses, not the logical contact id the revisions are
   * keyed by.
   */
  async function onRestore(revision: ContactRevisionPayload) {
    if (!session?.storage || !contactId) {
      return
    }
    setRestoreError(false)
    setRestoring(true)
    try {
      await session.storage.updateContact({
        id: contactId,
        contact: revision.snapshot,
        action: 'restore'
      })
    } catch (err) {
      console.error('Could not restore this contact version:', err)
      setRestoreError(true)
      setRestoring(false)
      return
    }
    // Posted to the global toast store rather than local state: navigate()
    // below leaves this page, so only a store-backed message survives to be
    // shown on the page the user lands on.
    showToast({ message: t('contactHistory.restored') })
    navigate(`/contacts/${contactId}`)
  }

  /**
   * The DIDs a revision's snapshot carried, listed under the display name so
   * that an edit which only added or removed a DID reads as a distinct
   * revision rather than as a repeat of the one before it.
   */
  function renderSnapshotDids(revision: ContactRevisionPayload) {
    const dids = getDids(revision.snapshot)
    if (dids.length === 0) {
      return null
    }
    return (
      <Stack spacing={0.25} sx={{ mt: 0.5 }}>
        {dids.map(did => (
          <Typography
            key={did}
            variant="caption"
            color="text.secondary"
            sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}
          >
            {did}
          </Typography>
        ))}
      </Stack>
    )
  }

  /**
   * The expanded body of a revision: the snapshot's fields, line by line, and
   * the restore action.
   */
  function renderRevisionDetail(revision: ContactRevisionPayload) {
    return (
      <Box sx={{ mt: 1.5 }}>
        <Stack spacing={0.25}>
          {snapshotLines(revision.snapshot).map((line, index) => (
            <Typography key={`${index}-${line}`} variant="body2">
              {line}
            </Typography>
          ))}
        </Stack>
        <Button
          variant="outlined"
          size="small"
          sx={{ mt: 1.5 }}
          disabled={restoring}
          onClick={() => {
            void onRestore(revision)
          }}
        >
          {t('contactHistory.restore')}
        </Button>
      </Box>
    )
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
        {revisions.map((revision, index) => {
          const rowId = `${revision.timestamp}-${revision.writerId}-${index}`
          const expanded = expandedId === rowId
          return (
            <Box
              key={rowId}
              sx={{
                p: 2,
                borderRadius: 2,
                border: '1px solid',
                borderColor: 'divider'
              }}
            >
              <ButtonBase
                onClick={() => setExpandedId(expanded ? null : rowId)}
                aria-expanded={expanded}
                sx={{
                  display: 'block',
                  width: '100%',
                  textAlign: 'left',
                  borderRadius: 1
                }}
              >
                <Stack
                  direction="row"
                  spacing={1}
                  sx={{ alignItems: 'center' }}
                >
                  <Chip
                    size="small"
                    label={t(`contactHistory.actions.${revision.action}`)}
                    color={ACTION_COLOR[revision.action]}
                  />
                  <Typography variant="body2" color="text.secondary">
                    {formatDateTime({
                      date: new Date(revision.timestamp),
                      locale: i18n.language
                    })}
                  </Typography>
                </Stack>
                <Typography variant="body1" sx={{ mt: 1 }}>
                  {revision.snapshot.displayName}
                </Typography>
                {renderSnapshotDids(revision)}
                <Typography
                  variant="caption"
                  color="text.secondary"
                  sx={{ display: 'block', mt: 0.5 }}
                >
                  {t('contactHistory.writer', {
                    writerId: revision.writerId.slice(
                      0,
                      WRITER_ID_PREFIX_LENGTH
                    )
                  })}
                </Typography>
              </ButtonBase>
              <Collapse in={expanded} unmountOnExit>
                {renderRevisionDetail(revision)}
              </Collapse>
            </Box>
          )
        })}
      </Stack>
    )
  }

  return (
    <DashboardLayout title={t('contactHistory.title')}>
      <Button
        component={RouterLink}
        to={`/contacts/${contactId}`}
        startIcon={<MdArrowBack />}
        sx={storageStyles.backToStorageButton}
        variant="text"
      >
        {t('contactHistory.back')}
      </Button>

      {restoreError && (
        <Alert severity="error" sx={{ mt: 2 }}>
          {t('contactHistory.restoreError')}
        </Alert>
      )}
      {loading ? <LoadingSpinner /> : renderRevisions()}
    </DashboardLayout>
  )
}
