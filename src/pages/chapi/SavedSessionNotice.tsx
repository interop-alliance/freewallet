/**
 * Saved-login recognition for the CHAPI popup pages (the popup half of
 * refresh-surviving sessions). Inside the mediator popup
 * the wallet loads as a third-party iframe whose IndexedDB is partitioned;
 * on Chrome, the Storage Access API beyond-cookies handle reaches the
 * first-party bucket where the top-level wallet persisted the session key
 * and delegated zcaps. This component runs that flow: a silent attempt on
 * mount (succeeds without a gesture when the permission was granted
 * before), and a button-driven attempt (the user gesture Chrome's first
 * prompt requires). On success it restores the delegated session and shows
 * who is signed in.
 *
 * For now, every popup operation (vault decrypt, DIDAuth) still needs
 * the passphrase -- so the parent keeps its login form; this notice adds
 * recognition ("you have a wallet here") and hands the first-party storage
 * factory up so a subsequent full login persists where the next popup
 * visit will find it.
 */
import { useEffect, useRef, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import { WAS_SERVER_URL } from '@/app.config'
import {
  requestFirstPartyStorage,
  storageAccessAvailable
} from '@/lib/storageAccess'
import { restoreDelegatedSession } from '@/session/delegatedSession'

type NoticeState = 'idle' | 'checking' | 'restored' | 'none' | 'unavailable'

/** Shortens a DID for display when the record carries no email. */
function displayIdentity({ id, email }: { id: string; email?: string }) {
  if (email) {
    return email
  }
  return id.length > 28 ? `${id.slice(0, 28)}...` : id
}

interface SavedSessionNoticeProps {
  /**
   * Fired when first-party storage was reached (whether or not a saved
   * session was found there): the page persists a subsequent full login
   * through this factory so the next popup visit auto-recognizes.
   */
  onFirstPartyStorage: (idb: IDBFactory) => void
}

export function SavedSessionNotice({
  onFirstPartyStorage
}: SavedSessionNoticeProps) {
  const { t } = useTranslation()
  const [state, setState] = useState<NoticeState>('idle')
  const [identity, setIdentity] = useState('')
  const attempted = useRef(false)

  // Without a remote WAS server no delegated session is ever persisted; and
  // without the Storage Access API (or outside an iframe) there is no
  // partitioned bucket to escape.
  const enabled = !!WAS_SERVER_URL && storageAccessAvailable()

  async function attempt({ silent }: { silent: boolean }) {
    setState('checking')
    try {
      const storage = await requestFirstPartyStorage()
      if (!storage) {
        // Silent attempts fail routinely (no prior grant, no gesture): fall
        // back to offering the button. An explicit attempt that fails means
        // this browser cannot reach the saved login at all.
        setState(silent ? 'idle' : 'unavailable')
        return
      }
      onFirstPartyStorage(storage.idb)
      const session = await restoreDelegatedSession({ idb: storage.idb })
      if (!session) {
        setState('none')
        return
      }
      setIdentity(displayIdentity(session.user))
      setState('restored')
    } catch (err) {
      console.warn('Saved-login restore failed:', err)
      setState(silent ? 'idle' : 'unavailable')
    }
  }

  useEffect(() => {
    // One silent attempt per mount (ref-guarded against StrictMode's
    // double-invoke): with a prior storage-access grant it succeeds without
    // a user gesture, so returning users are recognized with zero clicks.
    if (!enabled || attempted.current) {
      return
    }
    attempted.current = true
    void attempt({ silent: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled])

  if (!enabled) {
    return null
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
      {state === 'idle' && (
        <Button
          variant="outlined"
          size="small"
          sx={{ alignSelf: 'flex-start', textTransform: 'none' }}
          onClick={() => void attempt({ silent: false })}
        >
          {t('chapi.savedSession.button')}
        </Button>
      )}
      {state === 'checking' && (
        <Typography variant="body2" color="text.secondary">
          {t('chapi.savedSession.checking')}
        </Typography>
      )}
      {state === 'restored' && (
        <Typography variant="body2" color="success.main">
          {t('chapi.savedSession.restored', { identity })}
        </Typography>
      )}
      {state === 'none' && (
        <Typography variant="body2" color="text.secondary">
          {t('chapi.savedSession.none')}
        </Typography>
      )}
      {state === 'unavailable' && (
        <Typography variant="body2" color="text.secondary">
          {t('chapi.savedSession.unavailable')}
        </Typography>
      )}
    </Box>
  )
}
