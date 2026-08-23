/**
 * Settings section for the wallets connected to the account: lists
 * the enrolled wallet clients from the locally verified did:webvh log (a
 * recovery code's keyAgreement-only key never appears, and apps are never
 * enrolled -- they stay in the Applications surface), marks the client this
 * session runs in, renames clients (labels live in
 * `key-map/client-labels.json`; the document carries key material only),
 * starts the connect-another-wallet ceremony (one card offering both the QR
 * invite and the pasted connect code), and disconnects a client by
 * driving the full revocation cascade -- with honest copy about the last
 * enrolled client (disconnecting it would abandon update authority; a
 * recovery code is the answer to "my only browser is gone").
 */
import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import Chip from '@mui/material/Chip'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import IconButton from '@mui/material/IconButton'
import Link from '@mui/material/Link'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { MdEdit } from 'react-icons/md'
import { Link as RouterLink } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useCallback, useEffect, useState } from 'react'
import {
  enrollmentClientDid,
  parseEnrollmentRequest,
  type EnrollmentRequest
} from '@interop/wallet-core/enrollment'
import type { Session } from '@/types/auth'
import {
  canManageAccountClients,
  cascadeCompletion,
  disconnectAccountClient,
  disconnectEligibility,
  listAccountClients,
  renameAccountClient,
  type AccountClientView
} from '@/session/clients'
import { approveEnrollment } from '@/lib/enrollment'
import { forgetThisBrowser } from '@/session/forget'
import { OnboardInviteCard } from '@/components/OnboardInviteCard'
import { formatDate } from '@/lib/viewMappers/formatDate'
import { showToast } from '@/stores/toastStore'

/**
 * Whether a connect-code parse failure is the canonicality refusal -- a code
 * whose key-agreement key is not the canonical X25519 twin of its signing
 * key. wallet-core throws a plain `Error` for it, so the message is the only
 * handle; anything else falls back to the generic invalid-code copy.
 *
 * @param options {object}
 * @param options.err {unknown}   the error `parseEnrollmentRequest` threw
 * @returns {boolean}
 */
function isCanonicalKeyRefusal({ err }: { err: unknown }): boolean {
  return /canonical X25519 twin/i.test((err as Error)?.message ?? '')
}

export function EnrolledClientsSection({ session }: { session: Session }) {
  const { t, i18n } = useTranslation()
  const canManage = canManageAccountClients({ session })
  // `null` = not loaded yet (or the listing failed; `loadError` tells apart).
  const [clients, setClients] = useState<AccountClientView[] | null>(null)
  const [loadError, setLoadError] = useState(false)
  // Inline label editing: one row at a time, keyed by signing multibase.
  const [editingKey, setEditingKey] = useState<string | null>(null)
  const [labelDraft, setLabelDraft] = useState('')
  const [labelSaving, setLabelSaving] = useState(false)
  // The disconnect confirm dialog and its cascade run.
  const [disconnectTarget, setDisconnectTarget] =
    useState<AccountClientView | null>(null)
  const [disconnecting, setDisconnecting] = useState(false)
  const [disconnectError, setDisconnectError] = useState(false)
  const [cascadeWarning, setCascadeWarning] = useState(false)
  // The forget-this-browser confirm dialog and its ceremony run.
  const [forgetOpen, setForgetOpen] = useState(false)
  const [forgetting, setForgetting] = useState(false)
  const [forgetErrorKey, setForgetErrorKey] = useState<string | null>(null)
  // Interpolation values for the forget error copy (the unreachable sign-in
  // methods' labels when a record re-mint refused the removal).
  const [forgetErrorValues, setForgetErrorValues] = useState<
    Record<string, string>
  >({})
  // Which forget the open dialog confirms: the ordinary ceremony, or the
  // last-client transition (set from the listing when the dialog opens, and
  // flipped by the ceremony's own refusal when the listing was stale).
  const [forgetLastClient, setForgetLastClient] = useState(false)
  // The paste-code half of the connect card (the enrolling side): the pasted
  // connect code, its parsed request when valid, the new client's label, and
  // the ceremony state. Independent of the QR invite the same card shows:
  // they are two ways into the same ceremony, never one state machine.
  const [enrollCode, setEnrollCode] = useState('')
  const [enrollRequest, setEnrollRequest] = useState<EnrollmentRequest | null>(
    null
  )
  // Which refusal the pasted code met, as an i18n key -- `null` while the
  // code is empty or parses.
  const [enrollCodeErrorKey, setEnrollCodeErrorKey] = useState<string | null>(
    null
  )
  const [enrollLabel, setEnrollLabel] = useState('')
  const [enrolling, setEnrolling] = useState(false)
  const [enrollDone, setEnrollDone] = useState(false)
  const [enrollError, setEnrollError] = useState(false)
  const [connectCardOpen, setConnectCardOpen] = useState(false)
  const [onboardDone, setOnboardDone] = useState(false)

  const loadClients = useCallback(async () => {
    try {
      const listed = await listAccountClients({ session })
      setClients(listed)
      setLoadError(false)
    } catch (err) {
      console.warn('Could not list the enrolled wallet clients:', err)
      setLoadError(true)
    }
  }, [session])

  // The initial load polls: right after signup the did:webvh provisioning
  // (and the pointer promotion `canManageAccountClients` gates on) still runs
  // in the background, so the first attempts may find no log yet. Polling
  // stops on the first successful listing, or after ~1 minute for sessions
  // that can never manage clients (no storage server configured).
  useEffect(() => {
    let cancelled = false
    let attempts = 0
    let timer: ReturnType<typeof setTimeout> | undefined
    async function attemptLoad() {
      attempts++
      if (canManageAccountClients({ session })) {
        try {
          const listed = await listAccountClients({ session })
          if (!cancelled) {
            setClients(listed)
            setLoadError(false)
          }
          return
        } catch (err) {
          console.warn('Could not list the enrolled wallet clients:', err)
          if (!cancelled) {
            setLoadError(true)
          }
        }
      }
      if (!cancelled && attempts < 15) {
        timer = setTimeout(() => void attemptLoad(), 4000)
      }
    }
    void attemptLoad()
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [session])

  const handleSaveLabel = async (client: AccountClientView) => {
    const trimmed = labelDraft.trim()
    if (!trimmed || trimmed === client.label) {
      setEditingKey(null)
      return
    }
    setLabelSaving(true)
    try {
      await renameAccountClient({
        session,
        signingKeyMultibase: client.signingKeyMultibase,
        label: trimmed
      })
      setEditingKey(null)
      showToast({ message: t('settings.clients.labelSaved') })
      await loadClients()
    } catch (err) {
      console.error('Could not rename the wallet client:', err)
      showToast({ message: t('settings.clients.labelSaveFailed') })
    } finally {
      setLabelSaving(false)
    }
  }

  /**
   * Runs the full disconnect cascade for the confirmed client. Every stage
   * after the account-log edit converges under a re-run (and the login-time
   * sweep is the standing backstop), so a failure or partial completion is
   * surfaced with "run it again" copy rather than treated as fatal.
   */
  const handleDisconnect = async () => {
    const target = disconnectTarget
    if (!target || disconnecting) {
      return
    }
    setDisconnecting(true)
    setDisconnectError(false)
    setCascadeWarning(false)
    try {
      const outcome = await disconnectAccountClient({
        session,
        client: target
      })
      setDisconnectTarget(null)
      // A partial collection fan-out is a resumable success, never an error:
      // the wallet IS disconnected (the document edit landed first), and the
      // login-time sweep finishes the re-keying.
      if (
        cascadeCompletion({ collections: outcome.collections }) === 'partial'
      ) {
        setCascadeWarning(true)
      } else {
        showToast({ message: t('settings.clients.disconnected') })
      }
      await loadClients()
    } catch (err) {
      console.error('Could not disconnect the wallet client:', err)
      setDisconnectError(true)
    } finally {
      setDisconnecting(false)
    }
  }

  /**
   * Runs the forget ceremony for THIS browser: the roster rotation and
   * collection fan-out under this client's still-standing authority, one
   * ladder-signed removal entry through the login credential's bridge, then
   * the shared local wipe -- and ends at the logout page, since the session's
   * local footing is gone. A torn run reads as "not forgotten" (the wipe
   * runs last), so the dialog's retry copy is honest: a re-click resumes.
   * The account's last durable client runs the two-entry transition instead
   * (confirmed against its own copy); a listing that turned out stale -- the
   * ordinary ceremony's name-stable refusal -- flips the dialog to the
   * transition copy for a second confirm rather than running it unconfirmed.
   * The transition also refuses up front, name-stably
   * (`PendingRetirementForgetError`), when a passphrase change on the
   * account was torn before its retirement landed: only a durable login can
   * finish that change, and the transition ends durable logins forever.
   * The transition's other name-stable refusal, `RecordRemintFailedError`,
   * is a retryable stop, not a failure: another sign-in method's record
   * could not be re-sealed, so the removal entry was withheld and this
   * browser is still connected. The copy names those methods, and a re-click
   * resumes at the re-mint.
   */
  const handleForget = async () => {
    if (forgetting) {
      return
    }
    setForgetting(true)
    setForgetErrorKey(null)
    setForgetErrorValues({})
    try {
      const outcome = await forgetThisBrowser({
        session,
        lastClient: forgetLastClient
      })
      if (outcome.wipeFailed.length > 0) {
        // Residue is self-healing: a surviving replica or trio is finished
        // by the next login's forgotten-browser detector.
        console.warn('The forget wipe left residue behind:', outcome.wipeFailed)
      }
      if (outcome.wipeUnverified.length > 0) {
        // Deleted, but not confirmed (this browser cannot enumerate its
        // databases); the same detector settles it at the next login.
        console.warn(
          'The forget wipe could not confirm these stages:',
          outcome.wipeUnverified
        )
      }
      if (outcome.lastClient && outcome.ceremony.unlockMethods) {
        // The other sign-in methods' record re-mint report: a `failed`
        // outcome never reaches here (it refuses the removal), so what is
        // left to note is an entry predating the re-mint fields, which the
        // pass skips and the recovery health check keeps flagging.
        const skipped = outcome.ceremony.unlockMethods.outcomes.filter(
          entry => entry.outcome === 'incomplete-entry'
        )
        if (skipped.length > 0) {
          console.warn(
            'The last-client forget skipped sign-in records predating the ' +
              're-mint fields:',
            skipped.map(entry => entry.label)
          )
        }
      }
      // A hard reload, not a router navigate: the wipe just deleted the
      // storage this tab's in-memory handles point at (the guest-wipe logout
      // takes the same exit).
      window.location.href = '/login'
    } catch (err) {
      const name = (err as { name?: string })?.name
      if (name === 'LastDurableClientForgetError') {
        setForgetLastClient(true)
        setForgetErrorKey('settings.forget.lastClientNow')
      } else if (name === 'PendingRetirementForgetError') {
        console.warn('The last-client forget refused a pending change:', err)
        setForgetErrorKey('settings.forget.pendingRetirement')
      } else if (name === 'RecordRemintFailedError') {
        console.warn('The last-client forget withheld the removal:', err)
        const failed = (err as { failed?: Array<{ label: string }> }).failed
        setForgetErrorValues({
          methods: (failed ?? []).map(outcome => outcome.label).join(', ')
        })
        setForgetErrorKey('settings.forget.recordsUnreachable')
      } else {
        console.error('Could not forget this browser:', err)
        setForgetErrorKey('settings.forget.failed')
      }
    } finally {
      setForgetting(false)
    }
  }

  /**
   * Tracks the pasted connect code, parsing it eagerly so the dialog can show
   * the new client's key fingerprint (for the on-screen comparison) before
   * anything is approved.
   *
   * A code whose key-agreement key is not the canonical X25519 twin of its
   * signing key is refused by the parse itself, before anything is published,
   * and gets its own copy: nothing about it can be fixed by re-typing, so
   * "not a valid connect code" would send the person looking in the wrong
   * place.
   */
  const handleEnrollCodeChange = (code: string) => {
    setEnrollCode(code)
    setEnrollError(false)
    if (!code.trim()) {
      setEnrollRequest(null)
      setEnrollCodeErrorKey(null)
      return
    }
    try {
      setEnrollRequest(parseEnrollmentRequest({ code }))
      setEnrollCodeErrorKey(null)
    } catch (err) {
      setEnrollRequest(null)
      setEnrollCodeErrorKey(
        isCanonicalKeyRefusal({ err })
          ? 'settings.enrollCodeNotCanonical'
          : 'settings.enrollCodeInvalid'
      )
    }
  }

  /**
   * Runs the enrollment ceremony for the pasted connect code, in the push
   * order (the user key wrap into the roster first, then the two log entries),
   * saving the chosen label once the ceremony lands. Idempotent -- approving
   * the same code again after a failure resumes.
   */
  const handleEnroll = async () => {
    if (!enrollRequest || enrolling) {
      return
    }
    setEnrolling(true)
    setEnrollError(false)
    try {
      await approveEnrollment({
        request: enrollRequest,
        session,
        label: enrollLabel
      })
      setEnrollDone(true)
      setConnectCardOpen(false)
      setEnrollCode('')
      setEnrollRequest(null)
      setEnrollCodeErrorKey(null)
      await loadClients()
    } catch (err) {
      console.error('Enrolling the new wallet client failed:', err)
      setEnrollError(true)
    } finally {
      setEnrolling(false)
    }
  }

  const canEnroll = canManage
  const lastClient = (clients?.length ?? 0) <= 1

  return (
    <Stack sx={{ gap: 1 }}>
      <Typography variant="h6">{t('settings.clients.section')}</Typography>
      <Typography variant="body2" color="text.secondary">
        {t('settings.clients.intro')}
      </Typography>

      {!canManage && (
        <Typography variant="body2" color="text.secondary">
          {t('settings.clients.requiresAccount')}
        </Typography>
      )}

      {canManage && loadError && (
        <Alert severity="warning">{t('settings.clients.loadError')}</Alert>
      )}

      {clients !== null && clients.length > 0 && (
        <Stack sx={{ gap: 1.5, mt: 1 }} data-testid="enrolled-clients-list">
          {clients.map(client => {
            const editing = editingKey === client.signingKeyMultibase
            const displayName = client.label ?? t('settings.clients.unlabeled')
            // The shared policy, not UI state: self and last-wallet hide the
            // button entirely, an unattributed update key disables it.
            const eligibility = disconnectEligibility({ client, clients })
            return (
              <Card
                key={client.signingKeyMultibase}
                variant="outlined"
                sx={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 0.5,
                  p: 1.5
                }}
              >
                <Stack
                  direction="row"
                  sx={{ alignItems: 'center', gap: 1, flexWrap: 'wrap' }}
                >
                  {editing ? (
                    <>
                      <TextField
                        size="small"
                        label={t('settings.clients.nameLabel')}
                        value={labelDraft}
                        onChange={event => setLabelDraft(event.target.value)}
                        sx={{ minWidth: 220 }}
                      />
                      <Button
                        variant="contained"
                        size="small"
                        loading={labelSaving}
                        disabled={labelDraft.trim().length === 0}
                        onClick={() => void handleSaveLabel(client)}
                      >
                        {t('common.save')}
                      </Button>
                      <Button
                        size="small"
                        disabled={labelSaving}
                        onClick={() => setEditingKey(null)}
                      >
                        {t('common.cancel')}
                      </Button>
                    </>
                  ) : (
                    <>
                      <Typography variant="body1">{displayName}</Typography>
                      <Tooltip title={t('common.edit')}>
                        <IconButton
                          size="small"
                          aria-label={t('common.edit')}
                          onClick={() => {
                            setLabelDraft(client.label ?? '')
                            setEditingKey(client.signingKeyMultibase)
                          }}
                          sx={{ p: 0.25 }}
                        >
                          <MdEdit size={15} />
                        </IconButton>
                      </Tooltip>
                      {client.isCurrent && (
                        <Chip
                          size="small"
                          color="primary"
                          label={t('settings.clients.thisBrowser')}
                        />
                      )}
                    </>
                  )}
                </Stack>
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{ wordBreak: 'break-all' }}
                >
                  {t('settings.clients.keyFingerprint', {
                    did: `did:key:${client.signingKeyMultibase}`
                  })}
                </Typography>
                {client.addedAt && (
                  <Typography variant="body2" color="text.secondary">
                    {t('settings.clients.connectedOn', {
                      date: formatDate({
                        isoDate: client.addedAt,
                        locale: i18n.language
                      })
                    })}
                  </Typography>
                )}
                {eligibility.refusal !== 'self' &&
                  eligibility.refusal !== 'last-client' && (
                    <Button
                      variant="outlined"
                      size="small"
                      color="error"
                      sx={{ borderRadius: 2, alignSelf: 'flex-start' }}
                      disabled={disconnecting || !eligibility.allowed}
                      onClick={() => {
                        setDisconnectError(false)
                        setCascadeWarning(false)
                        setDisconnectTarget(client)
                      }}
                    >
                      {t('settings.clients.disconnect')}
                    </Button>
                  )}
                {eligibility.refusal === 'self' &&
                  session.profile.standingUnlock !== undefined &&
                  session.profile.ladderSeed !== undefined && (
                    // The self row's exit is the forget ceremony, not a
                    // disconnect: this browser removes ITSELF through the
                    // login credential's bridge and wipes its local state.
                    // Needs the standing members the login carried; a
                    // session without them (an enrollment-completion login)
                    // simply does not offer it.
                    <Button
                      variant="outlined"
                      size="small"
                      color="error"
                      sx={{ borderRadius: 2, alignSelf: 'flex-start' }}
                      disabled={forgetting}
                      onClick={() => {
                        setForgetErrorKey(null)
                        setForgetLastClient(lastClient)
                        setForgetOpen(true)
                      }}
                      data-testid="forget-this-browser-button"
                    >
                      {t('settings.forget.button')}
                    </Button>
                  )}
              </Card>
            )
          })}
        </Stack>
      )}

      {clients !== null && lastClient && (
        <Typography variant="body2" color="text.secondary">
          {t('settings.clients.lastClientHint')}
        </Typography>
      )}

      {cascadeWarning && (
        <Alert severity="warning">
          {t('settings.clients.cascadeIncomplete')}
        </Alert>
      )}

      {canEnroll && (
        <Stack
          direction="row"
          sx={{ alignItems: 'center', flexWrap: 'wrap', gap: 2, mt: 1 }}
        >
          <Button
            variant="outlined"
            size="small"
            sx={{ borderRadius: 2, flexShrink: 0 }}
            disabled={connectCardOpen}
            onClick={() => {
              setEnrollDone(false)
              setOnboardDone(false)
              setEnrollError(false)
              setEnrollCode('')
              setEnrollRequest(null)
              setEnrollCodeErrorKey(null)
              setEnrollLabel(
                t('settings.clients.defaultLabel', {
                  number: (clients?.length ?? 1) + 1
                })
              )
              setConnectCardOpen(true)
            }}
          >
            {t('settings.connectClient')}
          </Button>
          <Typography variant="body2" color="text.secondary">
            {t('settings.connectClientHint')}
          </Typography>
        </Stack>
      )}
      {canEnroll && connectCardOpen && (
        <OnboardInviteCard
          session={session}
          onApproved={() => {
            setConnectCardOpen(false)
            setOnboardDone(true)
            void loadClients()
          }}
          onCancel={() => setConnectCardOpen(false)}
          cancelDisabled={enrolling}
          pasteSection={
            <Stack sx={{ gap: 1.5 }}>
              <Typography variant="body2" color="text.secondary">
                {t('settings.enrollConfirmMessage')}
              </Typography>
              <TextField
                fullWidth
                size="small"
                multiline
                minRows={3}
                label={t('settings.enrollCodeLabel')}
                value={enrollCode}
                onChange={event => handleEnrollCodeChange(event.target.value)}
                error={Boolean(enrollCodeErrorKey)}
                helperText={
                  enrollCodeErrorKey ? t(enrollCodeErrorKey) : undefined
                }
                slotProps={{
                  htmlInput: { 'data-testid': 'enroll-code-input' }
                }}
              />
              <TextField
                fullWidth
                size="small"
                label={t('settings.clients.nameLabel')}
                value={enrollLabel}
                onChange={event => setEnrollLabel(event.target.value)}
                slotProps={{
                  htmlInput: { 'data-testid': 'enroll-label-input' }
                }}
              />
              {enrollRequest && (
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{ wordBreak: 'break-all' }}
                >
                  {t('settings.enrollFingerprint', {
                    did: enrollmentClientDid({ request: enrollRequest })
                  })}
                </Typography>
              )}
              {enrollError && (
                <Alert severity="error">{t('settings.enrollError')}</Alert>
              )}
              <Button
                variant="contained"
                size="small"
                sx={{ alignSelf: 'flex-start', borderRadius: 2 }}
                loading={enrolling}
                disabled={!enrollRequest}
                onClick={() => void handleEnroll()}
              >
                {t('settings.enrollConfirmAction')}
              </Button>
            </Stack>
          }
        />
      )}
      {enrollDone && (
        <Typography variant="body2" color="success.main">
          {t('settings.enrollSuccess')}
        </Typography>
      )}
      {onboardDone && (
        <Typography variant="body2" color="success.main">
          {t('settings.onboardSuccess')}
        </Typography>
      )}

      <Typography variant="body2" color="text.secondary">
        {t('settings.clients.applicationsCrossPointer')}{' '}
        <Link component={RouterLink} to="/applications">
          {t('settings.clients.applicationsCrossPointerLink')}
        </Link>
        .
      </Typography>

      <Dialog
        open={disconnectTarget !== null}
        onClose={() => {
          if (!disconnecting) {
            setDisconnectTarget(null)
          }
        }}
        fullWidth
      >
        <DialogTitle>
          {t('settings.clients.disconnectConfirmTitle', {
            name: disconnectTarget?.label ?? t('settings.clients.unlabeled')
          })}
        </DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t('settings.clients.disconnectConfirmMessage')}
          </DialogContentText>
          {disconnecting && (
            <Alert severity="info" sx={{ mt: 2 }}>
              {t('settings.clients.disconnectProgress')}
            </Alert>
          )}
          {disconnectError && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {t('settings.clients.disconnectError')}
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => setDisconnectTarget(null)}
            disabled={disconnecting}
          >
            {t('common.cancel')}
          </Button>
          <Button
            variant="contained"
            color="error"
            loading={disconnecting}
            onClick={() => void handleDisconnect()}
          >
            {t('settings.clients.disconnectConfirmAction')}
          </Button>
        </DialogActions>
      </Dialog>

      {/* The forget-this-browser confirm (the forget ceremony). */}
      <Dialog
        open={forgetOpen}
        onClose={() => {
          if (!forgetting) {
            setForgetOpen(false)
          }
        }}
        fullWidth
      >
        <DialogTitle>
          {t(
            forgetLastClient
              ? 'settings.forget.lastClientTitle'
              : 'settings.forget.confirmTitle'
          )}
        </DialogTitle>
        <DialogContent>
          <Stack sx={{ gap: 1.5 }}>
            {forgetLastClient ? (
              // The transition copy: the account keeps no connected browser
              // and stays anchored by the sign-in credentials alone -- the
              // consequence the user confirms against.
              <>
                <DialogContentText data-testid="forget-last-client-copy">
                  {t('settings.forget.lastClientMessage')}
                </DialogContentText>
                <DialogContentText>
                  {t('settings.forget.lastClientConsequence')}
                </DialogContentText>
              </>
            ) : (
              <DialogContentText>
                {t('settings.forget.confirmMessage')}
              </DialogContentText>
            )}
            <DialogContentText>
              {t('settings.forget.confirmCeiling')}
            </DialogContentText>
          </Stack>
          {forgetting && (
            <Alert severity="info" sx={{ mt: 2 }}>
              {t(
                forgetLastClient
                  ? 'settings.forget.lastClientProgress'
                  : 'settings.forget.progress'
              )}
            </Alert>
          )}
          {forgetErrorKey && (
            <Alert
              severity={
                forgetErrorKey === 'settings.forget.lastClientNow'
                  ? 'info'
                  : 'error'
              }
              sx={{ mt: 2 }}
            >
              {t(forgetErrorKey, forgetErrorValues)}
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setForgetOpen(false)} disabled={forgetting}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="contained"
            color="error"
            loading={forgetting}
            onClick={() => void handleForget()}
            data-testid="forget-this-browser-confirm"
          >
            {t('settings.forget.confirmAction')}
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  )
}
