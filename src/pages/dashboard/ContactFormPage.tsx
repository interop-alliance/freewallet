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
import {
  buildContact,
  getDids,
  isDidUrl,
  type ContactData,
  type ContactFormRow
} from '@interop/social-core'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { useAuthStore } from '@/stores/authStore'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { contactFormStyles } from '@/styles/appStyles'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:contacts')

/**
 * One editable phone / email row: the shared form row, with `label` and
 * `value` narrowed to required strings because they are bound straight to
 * controlled text fields. `digits`, `countryCode` and `id` are carried through
 * from the loaded contact so an edit does not strip what an importer recorded;
 * `digits` / `countryCode` are derived from the number, so editing the value
 * clears them rather than leaving a stale pair behind.
 */
type LabeledRow = ContactFormRow & { label: string; value: string }

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

  // The full loaded ContactData when editing. buildContact() spreads it under
  // the form-bound fields so everything the form does not surface (nativeId,
  // middleName, prefix/suffix, jobTitle, department, postalAddresses,
  // imAddresses, urlAddresses, birthday, isStarred, ...) survives a save
  // instead of being silently stripped from the head payload.
  const [existingContact, setExistingContact] = useState<ContactData>()
  const [displayName, setDisplayName] = useState('')
  const [givenName, setGivenName] = useState('')
  const [familyName, setFamilyName] = useState('')
  const [organization, setOrganization] = useState('')
  const [note, setNote] = useState('')
  const [phoneNumbers, setPhoneNumbers] = useState<LabeledRow[]>([])
  const [emailAddresses, setEmailAddresses] = useState<LabeledRow[]>([])
  const [dids, setDids] = useState<string[]>([])
  // Row positions of DID fields that failed validation on the last save
  // attempt. Any edit to the DID list clears them, since a removal shifts the
  // positions of every row after it.
  const [invalidDidRows, setInvalidDidRows] = useState<number[]>([])

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
        setExistingContact(contact)
        setDisplayName(contact.displayName)
        setGivenName(contact.givenName ?? '')
        setFamilyName(contact.familyName ?? '')
        setOrganization(contact.organization ?? '')
        setNote(contact.note ?? '')
        setPhoneNumbers(
          (contact.phoneNumbers ?? []).map(phone => ({
            label: phone.label,
            value: phone.number,
            digits: phone.digits,
            countryCode: phone.countryCode,
            id: phone.id
          }))
        )
        setEmailAddresses(
          (contact.emailAddresses ?? []).map(email => ({
            label: email.label,
            value: email.email,
            id: email.id
          }))
        )
        // `getDids` dedupes, so a contact merged from another replica does not
        // present the same DID on two rows; `buildContact` dedupes again, for
        // the duplicate the user can still type in by hand.
        setDids(getDids(contact))
      } catch (err) {
        log.error('Could not load contact', { err })
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

  /**
   * Applies a patch to one row of a phone / email list.
   *
   * @param options {object}
   * @param options.rows {LabeledRow[]} The current list.
   * @param options.setRows {Function} Setter for the list.
   * @param options.index {number} Position of the row to patch.
   * @param options.patch {Partial<LabeledRow>} The members to overwrite.
   */
  function updateRow({
    rows,
    setRows,
    index,
    patch
  }: {
    rows: LabeledRow[]
    setRows: (rows: LabeledRow[]) => void
    index: number
    patch: Partial<LabeledRow>
  }) {
    setRows(
      rows.map((row, rowIndex) => {
        if (rowIndex !== index) {
          return row
        }
        // A changed value invalidates the number-derived `digits` /
        // `countryCode` an importer recorded, so drop them.
        const derived =
          patch.value === undefined
            ? {}
            : { digits: undefined, countryCode: undefined }
        return { ...row, ...patch, ...derived }
      })
    )
  }

  async function onSave() {
    if (!session?.storage) {
      return
    }
    // The shared assembly: trimming, label normalization, the carried-through
    // members, and folding the DID rows back into `urlAddresses` (non-DID
    // entries an importer recorded survive) all live in social-core, so an
    // edit made here serializes byte-identically to the same edit on mobile.
    const contact = buildContact({
      ...(existingContact ? { existing: existingContact } : {}),
      displayName,
      givenName,
      familyName,
      organization,
      note,
      phoneNumbers,
      emailAddresses,
      dids
    })
    if (!contact.displayName) {
      setErrorMessage(t('contactForm.errors.nameRequired'))
      return
    }
    // Reject anything the read side (`getDids`) would not surface: neither
    // `setDids` nor `buildContact` validates a row, so a typo'd entry would be
    // persisted and synced yet filtered out of every view, with no way to see
    // or remove it again. A blank row is fine -- the assembly drops it.
    const invalidRows = dids
      .map((did, index) => ({ did: did.trim(), index }))
      .filter(row => row.did && !isDidUrl(row.did))
      .map(row => row.index)
    if (invalidRows.length > 0) {
      setInvalidDidRows(invalidRows)
      setErrorMessage(t('contactForm.errors.invalidDid'))
      return
    }
    setInvalidDidRows([])
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
      log.error('Could not save contact', { err })
      setErrorMessage(t('contactForm.errors.saveFailed'))
    } finally {
      setSaving(false)
    }
  }

  /**
   * Renders one labeled-row section (phone numbers, email addresses): a
   * label / value field pair per row, plus the add and remove controls.
   *
   * @param options {object}
   * @param options.heading {string} Section heading.
   * @param options.valueLabel {string} Label for the value field.
   * @param options.rows {LabeledRow[]} The current list.
   * @param options.setRows {Function} Setter for the list.
   * @param options.testIdPrefix {string} Prefix for the per-row React keys.
   */
  function renderRows({
    heading,
    valueLabel,
    rows,
    setRows,
    testIdPrefix
  }: {
    heading: string
    valueLabel: string
    rows: LabeledRow[]
    setRows: (rows: LabeledRow[]) => void
    testIdPrefix: string
  }) {
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
              onChange={event =>
                updateRow({
                  rows,
                  setRows,
                  index,
                  patch: { label: event.target.value }
                })
              }
              label={t('contactForm.label')}
              size="small"
              sx={contactFormStyles.labelInput}
            />
            <TextField
              value={row.value}
              onChange={event =>
                updateRow({
                  rows,
                  setRows,
                  index,
                  patch: { value: event.target.value }
                })
              }
              label={valueLabel}
              size="small"
              fullWidth
            />
            <IconButton
              onClick={() =>
                setRows(rows.filter((_, rowIndex) => rowIndex !== index))
              }
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

  // DIDs are stored as urlAddresses entries with a fixed `label: 'did'` (see
  // buildContact()), so unlike renderRows() this only surfaces one text field
  // per row -- there's no user-editable label.
  function renderDids() {
    /**
     * Applies a DID-list edit and clears the standing validation state, so a
     * row error goes away as soon as the user touches the list.
     */
    function applyDidEdit(next: string[]) {
      setDids(next)
      if (invalidDidRows.length > 0) {
        setInvalidDidRows([])
        setErrorMessage('')
      }
    }

    return (
      <Box sx={contactFormStyles.rowsSection}>
        <Typography variant="overline" color="text.secondary">
          {t('contact.sections.dids')}
        </Typography>
        {dids.map((did, index) => (
          <Stack
            key={`contact-did-${index}`}
            direction="row"
            spacing={1}
            sx={contactFormStyles.rowGroup}
          >
            <TextField
              value={did}
              onChange={event =>
                applyDidEdit(
                  dids.map((row, rowIndex) =>
                    rowIndex === index ? event.target.value : row
                  )
                )
              }
              label={t('contactForm.did')}
              size="small"
              fullWidth
              error={invalidDidRows.includes(index)}
              helperText={
                invalidDidRows.includes(index)
                  ? t('contactForm.errors.invalidDid')
                  : undefined
              }
            />
            <IconButton
              onClick={() =>
                applyDidEdit(dids.filter((_, rowIndex) => rowIndex !== index))
              }
              aria-label={t('contactForm.removeRow')}
              size="small"
            >
              <MdRemoveCircleOutline />
            </IconButton>
          </Stack>
        ))}
        <Button
          size="small"
          onClick={() => applyDidEdit([...dids, ''])}
          startIcon={<MdAddCircleOutline />}
          sx={contactFormStyles.addRowButton}
        >
          {t('contactForm.addRow', { field: t('contact.sections.dids') })}
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
            onChange={event => {
              setDisplayName(event.target.value)
              if (errorMessage) {
                setErrorMessage('')
              }
            }}
            label={t('contactForm.displayName')}
            fullWidth
          />
          <TextField
            value={givenName}
            onChange={event => setGivenName(event.target.value)}
            label={t('contactForm.firstName')}
            fullWidth
          />
          <TextField
            value={familyName}
            onChange={event => setFamilyName(event.target.value)}
            label={t('contactForm.lastName')}
            fullWidth
          />
          <TextField
            value={organization}
            onChange={event => setOrganization(event.target.value)}
            label={t('contactForm.organization')}
            fullWidth
          />

          {renderRows({
            heading: t('contact.sections.phone'),
            valueLabel: t('contactForm.phoneNumber'),
            rows: phoneNumbers,
            setRows: setPhoneNumbers,
            testIdPrefix: 'contact-phone'
          })}
          {renderRows({
            heading: t('contact.sections.email'),
            valueLabel: t('contactForm.emailAddress'),
            rows: emailAddresses,
            setRows: setEmailAddresses,
            testIdPrefix: 'contact-email'
          })}
          {renderDids()}

          <TextField
            value={note}
            onChange={event => setNote(event.target.value)}
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
