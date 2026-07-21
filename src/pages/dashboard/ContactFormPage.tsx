import { useEffect, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import IconButton from '@mui/material/IconButton'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { MdAddCircleOutline, MdRemoveCircleOutline } from 'react-icons/md'
import { useNavigate, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import type { ContactData } from '@interop/social-core'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { useAuthStore } from '@/stores/authStore'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { contactFormStyles } from '@/styles/appStyles'

type LabeledRow = { label: string; value: string }

export function ContactFormPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { contactId } = useParams()
  const session = useAuthStore(state => state.session)
  const isEditing = Boolean(contactId)

  const [loading, setLoading] = useState(isEditing)
  const [notFound, setNotFound] = useState(false)
  const [saving, setSaving] = useState(false)
  const [errorMessage, setErrorMessage] = useState('')

  const [displayName, setDisplayName] = useState('')
  const [givenName, setGivenName] = useState('')
  const [familyName, setFamilyName] = useState('')
  const [organization, setOrganization] = useState('')
  const [note, setNote] = useState('')
  const [phoneNumbers, setPhoneNumbers] = useState<LabeledRow[]>([])
  const [emailAddresses, setEmailAddresses] = useState<LabeledRow[]>([])

  useEffect(() => {
    let cancelled = false

    async function loadExisting() {
      if (!isEditing || !session?.storage || !contactId) {
        return
      }
      try {
        const stored = await session.storage.loadContact({ id: contactId })
        if (cancelled) {
          return
        }
        if (!stored) {
          setNotFound(true)
          return
        }
        const { contact } = stored
        setDisplayName(contact.displayName)
        setGivenName(contact.givenName ?? '')
        setFamilyName(contact.familyName ?? '')
        setOrganization(contact.organization ?? '')
        setNote(contact.note ?? '')
        setPhoneNumbers(
          contact.phoneNumbers.map(p => ({ label: p.label, value: p.number }))
        )
        setEmailAddresses(
          contact.emailAddresses.map(e => ({ label: e.label, value: e.email }))
        )
      } catch (err) {
        console.error('Could not load contact:', err)
        setNotFound(true)
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }
    loadExisting()

    return () => {
      cancelled = true
    }
  }, [session, contactId, isEditing])

  function updateRow(
    rows: LabeledRow[],
    setRows: (rows: LabeledRow[]) => void,
    index: number,
    patch: Partial<LabeledRow>
  ) {
    setRows(rows.map((row, i) => (i === index ? { ...row, ...patch } : row)))
  }

  function buildContact(): ContactData {
    const trimmedName =
      displayName.trim() || `${givenName.trim()} ${familyName.trim()}`.trim()
    return {
      displayName: trimmedName,
      givenName: givenName.trim() || undefined,
      familyName: familyName.trim() || undefined,
      organization: organization.trim() || undefined,
      phoneNumbers: phoneNumbers
        .filter(row => row.value.trim())
        .map(row => ({
          label: row.label.trim() || 'other',
          number: row.value.trim()
        })),
      emailAddresses: emailAddresses
        .filter(row => row.value.trim())
        .map(row => ({
          label: row.label.trim() || 'other',
          email: row.value.trim()
        })),
      note: note.trim() || undefined
    }
  }

  async function onSave() {
    if (!session?.storage) {
      return
    }
    const contact = buildContact()
    if (!contact.displayName) {
      setErrorMessage(t('contactForm.errors.nameRequired'))
      return
    }
    setSaving(true)
    setErrorMessage('')
    try {
      if (isEditing && contactId) {
        await session.storage.updateContact({ id: contactId, contact })
        navigate(`/contacts/${contactId}`)
      } else {
        const stored = await session.storage.addContact({ contact })
        navigate(`/contacts/${stored.id}`)
      }
    } catch (err) {
      console.error('Could not save contact:', err)
      setErrorMessage(t('contactForm.errors.saveFailed'))
    } finally {
      setSaving(false)
    }
  }

  function renderRows(
    heading: string,
    valueLabel: string,
    rows: LabeledRow[],
    setRows: (rows: LabeledRow[]) => void,
    testIdPrefix: string
  ) {
    return (
      <Box sx={contactFormStyles.rowsSection}>
        <Typography variant="overline" color="text.secondary">
          {heading}
        </Typography>
        {rows.map((row, index) => (
          <Stack
            key={`${testIdPrefix}-${index}`}
            direction="row"
            spacing={1}
            sx={contactFormStyles.rowGroup}
          >
            <TextField
              value={row.label}
              onChange={e =>
                updateRow(rows, setRows, index, { label: e.target.value })
              }
              label={t('contactForm.label')}
              size="small"
              sx={contactFormStyles.labelInput}
            />
            <TextField
              value={row.value}
              onChange={e =>
                updateRow(rows, setRows, index, { value: e.target.value })
              }
              label={valueLabel}
              size="small"
              fullWidth
            />
            <IconButton
              onClick={() => setRows(rows.filter((_, i) => i !== index))}
              aria-label={t('contactForm.removeRow')}
              size="small"
            >
              <MdRemoveCircleOutline />
            </IconButton>
          </Stack>
        ))}
        <Button
          size="small"
          onClick={() => setRows([...rows, { label: '', value: '' }])}
          startIcon={<MdAddCircleOutline />}
          sx={contactFormStyles.addRowButton}
        >
          {t('contactForm.addRow', { field: heading })}
        </Button>
      </Box>
    )
  }

  if (isEditing && notFound) {
    return <NotFoundPage />
  }

  return (
    <DashboardLayout
      title={isEditing ? t('contactForm.editTitle') : t('contactForm.addTitle')}
    >
      {loading ? (
        <LoadingSpinner />
      ) : (
        <Box sx={contactFormStyles.form}>
          {errorMessage && (
            <Typography variant="body2" color="error">
              {errorMessage}
            </Typography>
          )}

          <TextField
            value={displayName}
            onChange={e => {
              setDisplayName(e.target.value)
              if (errorMessage) {
                setErrorMessage('')
              }
            }}
            label={t('contactForm.displayName')}
            fullWidth
          />
          <TextField
            value={givenName}
            onChange={e => setGivenName(e.target.value)}
            label={t('contactForm.firstName')}
            fullWidth
          />
          <TextField
            value={familyName}
            onChange={e => setFamilyName(e.target.value)}
            label={t('contactForm.lastName')}
            fullWidth
          />
          <TextField
            value={organization}
            onChange={e => setOrganization(e.target.value)}
            label={t('contactForm.organization')}
            fullWidth
          />

          {renderRows(
            t('contact.sections.phone'),
            t('contactForm.phoneNumber'),
            phoneNumbers,
            setPhoneNumbers,
            'contact-phone'
          )}
          {renderRows(
            t('contact.sections.email'),
            t('contactForm.emailAddress'),
            emailAddresses,
            setEmailAddresses,
            'contact-email'
          )}

          <TextField
            value={note}
            onChange={e => setNote(e.target.value)}
            label={t('contactForm.note')}
            multiline
            minRows={3}
            fullWidth
          />

          <Stack direction="row" spacing={2} sx={{ flexWrap: 'wrap' }}>
            <Button
              variant="contained"
              onClick={onSave}
              disabled={saving}
              sx={contactFormStyles.saveButton}
            >
              {saving ? t('common.saving') : t('common.save')}
            </Button>
            <Button
              variant="outlined"
              onClick={() =>
                navigate(
                  isEditing && contactId
                    ? `/contacts/${contactId}`
                    : '/contacts'
                )
              }
              disabled={saving}
              sx={contactFormStyles.saveButton}
            >
              {t('common.cancel')}
            </Button>
          </Stack>
        </Box>
      )}
    </DashboardLayout>
  )
}
