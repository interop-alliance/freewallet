import { useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
import Avatar from '@mui/material/Avatar'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import Divider from '@mui/material/Divider'
import IconButton from '@mui/material/IconButton'
import Stack from '@mui/material/Stack'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { MdContentCopy } from 'react-icons/md'
import { Link as RouterLink, useNavigate, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { useAuthStore } from '@/stores/authStore'
import { showToast } from '@/stores/toastStore'
import { useCopyToClipboard } from '@/hooks/useCopyToClipboard'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { contactDetailStyles } from '@/styles/appStyles'
import { getDids, initialsFor, type ContactData } from '@interop/social-core'

function FieldSection({
  label,
  rows
}: {
  label: string
  rows: { label: string; value: string }[]
}) {
  if (rows.length === 0) {
    return null
  }
  return (
    <Box sx={{ mt: 2 }}>
      <Typography variant="overline" color="text.secondary">
        {label}
      </Typography>
      {rows.map((row, index) => (
        <Stack
          key={`${row.label}-${index}`}
          direction="row"
          spacing={1}
          sx={{ mt: 0.5 }}
        >
          {row.label && (
            <Typography
              variant="body2"
              color="text.secondary"
              sx={{ minWidth: 72 }}
            >
              {row.label}
            </Typography>
          )}
          <Typography variant="body2">{row.value}</Typography>
        </Stack>
      ))}
    </Box>
  )
}

function DidListSection({
  dids,
  t
}: {
  dids: string[]
  t: (key: string) => string
}) {
  const { copied, copy } = useCopyToClipboard()
  // Tracked by row position rather than by DID value, since the stored list is
  // not guaranteed unique (see `uniqueDids` below): only the row that was
  // clicked should read "Copied!".
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null)

  async function handleCopy(did: string, index: number) {
    // Only claim the copy once it actually succeeded -- `copied` may still be
    // true from an earlier row, which would otherwise show "Copied!" over a
    // clipboard write that just failed (a non-secure context, say).
    if (await copy(did)) {
      setCopiedIndex(index)
    }
  }

  // A contact merged from another replica can carry the same DID twice; the
  // edit form collapses duplicates on save, but a contact that has not been
  // saved here yet still arrives with them, so the list shows each DID once.
  const uniqueDids = [...new Set(dids)]

  if (uniqueDids.length === 0) {
    return null
  }

  return (
    <Box sx={{ mt: 2 }}>
      <Typography variant="overline" color="text.secondary">
        {t('contact.sections.dids')}
      </Typography>
      <Stack component="ol" sx={contactDetailStyles.didList}>
        {uniqueDids.map((did, index) => (
          <Stack
            key={`${index}-${did}`}
            component="li"
            direction="row"
            sx={contactDetailStyles.didListItem}
          >
            <Typography variant="body2" sx={contactDetailStyles.didListIndex}>
              {index + 1}.
            </Typography>
            <Typography variant="body2" sx={contactDetailStyles.didListValue}>
              {did}
            </Typography>
            <Tooltip
              title={
                copied && copiedIndex === index
                  ? t('common.copied')
                  : t('common.copy')
              }
            >
              <IconButton
                size="small"
                onClick={() => {
                  void handleCopy(did, index)
                }}
                aria-label={t('common.copy')}
                sx={{ p: 0.25, flexShrink: 0 }}
              >
                <MdContentCopy size={15} />
              </IconButton>
            </Tooltip>
          </Stack>
        ))}
      </Stack>
    </Box>
  )
}

/**
 * Builds the "details" section rows (name parts and organization) for a
 * contact, skipping the members it does not carry.
 *
 * @param options {object}
 * @param options.contact {ContactData} The contact being displayed.
 * @param options.t {Function} The i18n translation function.
 * @returns {object[]} The label / value rows.
 */
function nameRowsFor({
  contact,
  t
}: {
  contact: ContactData
  t: (key: string) => string
}): { label: string; value: string }[] {
  const rows: { label: string; value: string }[] = []
  if (contact.givenName) {
    rows.push({ label: t('contactForm.firstName'), value: contact.givenName })
  }
  if (contact.familyName) {
    rows.push({ label: t('contactForm.lastName'), value: contact.familyName })
  }
  if (contact.organization) {
    rows.push({
      label: t('contactForm.organization'),
      value: contact.organization
    })
  }
  return rows
}

export function ContactDetailPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { contactId } = useParams()
  const session = useAuthStore(state => state.session)
  const [contact, setContact] = useState<ContactData | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false

    async function initialLoad() {
      if (!session?.storage || !contactId) {
        return
      }
      try {
        const stored = await session.storage.loadContact({ id: contactId })
        if (!cancelled) {
          setContact(stored?.contact ?? null)
        }
      } catch (err) {
        console.error('Could not load contact:', err)
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
  }, [session, contactId])

  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState(false)

  async function onConfirmDelete() {
    if (!session || !contactId) {
      return
    }
    setDeleteError(false)
    setDeleting(true)
    try {
      await session.storage.deleteContact({ id: contactId })
    } catch (err) {
      console.error('Error deleting contact:', err)
      setDeleteError(true)
      setDeleting(false)
      setDeleteDialogOpen(false)
      return
    }
    setDeleteDialogOpen(false)
    // Posted to the global toast store rather than local state: navigate()
    // below leaves this page, so only a store-backed message survives to be
    // shown on the page the user lands on.
    showToast({ message: t('contact.deleted') })
    navigate('/contacts')
  }

  if (!contactId) {
    return <NotFoundPage />
  }

  if (loading) {
    return (
      <DashboardLayout title={t('contactDetail.title')}>
        <LoadingSpinner />
      </DashboardLayout>
    )
  }

  if (!contact) {
    return <NotFoundPage />
  }

  return (
    <DashboardLayout title={t('contactDetail.title')}>
      {deleteError && (
        <Alert severity="error" sx={{ mt: 2 }}>
          {t('contact.deleteError')}
        </Alert>
      )}

      <Card sx={contactDetailStyles.card}>
        <CardContent sx={contactDetailStyles.cardContent}>
          <Stack direction="row" spacing={2} sx={contactDetailStyles.headerRow}>
            <Avatar sx={contactDetailStyles.avatar}>
              {initialsFor(contact.displayName)}
            </Avatar>
            <Typography variant="h4" sx={contactDetailStyles.name}>
              {contact.displayName}
            </Typography>
          </Stack>

          <Divider sx={{ mt: 2 }} />

          <FieldSection
            label={t('contact.sections.details')}
            rows={nameRowsFor({ contact, t })}
          />
          <FieldSection
            label={t('contact.sections.phone')}
            rows={(contact.phoneNumbers ?? []).map(phone => ({
              label: phone.label,
              value: phone.number
            }))}
          />
          <FieldSection
            label={t('contact.sections.email')}
            rows={(contact.emailAddresses ?? []).map(email => ({
              label: email.label,
              value: email.email
            }))}
          />
          <DidListSection dids={getDids(contact)} t={t} />
          {contact.note && (
            <FieldSection
              label={t('contact.sections.note')}
              rows={[{ label: '', value: contact.note }]}
            />
          )}

          <Stack direction="row" spacing={1.5} sx={contactDetailStyles.actions}>
            <Button
              variant="outlined"
              component={RouterLink}
              to={`/contacts/${contactId}/edit`}
            >
              {t('common.edit')}
            </Button>
            <Button
              variant="outlined"
              component={RouterLink}
              to={`/contacts/${contactId}/history`}
            >
              {t('contact.history')}
            </Button>
            <Button
              variant="outlined"
              color="error"
              onClick={() => setDeleteDialogOpen(true)}
            >
              {t('common.delete')}
            </Button>
          </Stack>
        </CardContent>
      </Card>

      <Dialog
        open={deleteDialogOpen}
        onClose={() => setDeleteDialogOpen(false)}
      >
        <DialogTitle>{t('contact.deleteDialog.title')}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t('contact.deleteDialog.message', {
              name: contact.displayName
            })}
          </DialogContentText>
        </DialogContent>
        <DialogActions sx={{ gap: 1, px: 3, pb: 2 }}>
          <Button
            onClick={() => setDeleteDialogOpen(false)}
            disabled={deleting}
          >
            {t('common.cancel')}
          </Button>
          <Button
            onClick={onConfirmDelete}
            color="error"
            variant="contained"
            disabled={deleting}
          >
            {t('common.delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </DashboardLayout>
  )
}
