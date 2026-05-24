import { useCallback, useRef, useState } from 'react'
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  Alert,
  CircularProgress,
  Box
} from '@mui/material'
import QrScanner from 'qr-scanner'
import { useTranslation } from 'react-i18next'
import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import { resolveCredentialsInput } from '@/lib/resolveCredentialsInput'
import { resolveCredentialsInputErrorMessage } from '@/lib/resolveCredentialsInputErrorMessage'
import {
  scanCredentialQrStyles,
  scanCredentialQrVideoStyle
} from '@/styles/scanCredentialQrStyles'

type QrDecodedPayload = {
  data: string
}

type ScanCredentialQrDialogProps = {
  open: boolean
  onClose: () => void
  /**
   * Same acceptance flow as Add Credential (review screen before storing).
   */
  onCredentialsReady: (credentials: IVerifiableCredential[]) => void
}

export function ScanCredentialQrDialog({
  open,
  onClose,
  onCredentialsReady
}: ScanCredentialQrDialogProps) {
  const { t } = useTranslation()
  const scannerRef = useRef<QrScanner | null>(null)
  const [decodeError, setDecodeError] = useState<string | null>(null)
  const [startingCamera, setStartingCamera] = useState(false)
  const [cameraBlocked, setCameraBlocked] = useState(false)

  const destroyScanner = useCallback(() => {
    scannerRef.current?.destroy()
    scannerRef.current = null
  }, [])

  const onScanFail = useCallback(
    (error: Error | string) => {
      const msg = typeof error === 'string' ? error : error.message
      if (msg !== QrScanner.NO_QR_CODE_FOUND) {
        setDecodeError(t('dashboard.scanQr.scanEngineError'))
        destroyScanner()
      }
    },
    [destroyScanner, t]
  )

  const onScanSuccess = useCallback(
    async (result: string | QrDecodedPayload) => {
      const sc = scannerRef.current
      if (!sc) {
        return
      }
      const data = typeof result === 'string' ? result : result.data
      try {
        sc.stop()
        const credentials = await resolveCredentialsInput(data)
        onCredentialsReady(credentials)
      } catch (err) {
        setDecodeError(
          resolveCredentialsInputErrorMessage(err, t, { trimmed: data })
        )
        sc.start().catch(() => {})
      }
    },
    [onCredentialsReady, t]
  )

  const handleClose = useCallback(() => {
    setDecodeError(null)
    setStartingCamera(false)
    setCameraBlocked(false)
    onClose()
  }, [onClose])

  const attachVideoRef = useCallback(
    (video: HTMLVideoElement | null) => {
      destroyScanner()

      if (!video) {
        setDecodeError(null)
        setStartingCamera(false)
        setCameraBlocked(false)
        return
      }

      if (!open) {
        return
      }

      setStartingCamera(true)
      setDecodeError(null)
      setCameraBlocked(false)

      try {
        const scanner = new QrScanner(video, onScanSuccess, {
          onDecodeError: onScanFail,
          preferredCamera: 'environment',
          highlightScanRegion: true,
          highlightCodeOutline: true,
          returnDetailedScanResult: true
        })
        scannerRef.current = scanner
        scanner
          .start()
          .catch(() => {
            setCameraBlocked(true)
            setDecodeError(t('dashboard.scanQr.cameraError'))
          })
          .finally(() => {
            setStartingCamera(false)
          })
      } catch {
        setStartingCamera(false)
        setCameraBlocked(true)
        setDecodeError(t('dashboard.scanQr.cameraError'))
      }
    },
    [destroyScanner, open, onScanFail, onScanSuccess, t]
  )

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ pb: 1 }}>
        <Typography variant="h6" component="span">
          {t('dashboard.scanQr.title')}
        </Typography>
      </DialogTitle>
      <DialogContent sx={{ pt: 0 }}>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {t('dashboard.scanQr.hint')}
        </Typography>
        {cameraBlocked ? (
          <Alert severity="warning" sx={{ mb: 2 }}>
            {t('dashboard.scanQr.cameraPermissionHint')}
          </Alert>
        ) : null}
        {open ? (
          <Box sx={scanCredentialQrStyles.previewContainer}>
            <video
              ref={attachVideoRef}
              muted
              playsInline
              style={scanCredentialQrVideoStyle}
            />
            {startingCamera ? (
              <CircularProgress
                size={36}
                sx={{
                  position: 'absolute',
                  color: 'common.white'
                }}
              />
            ) : null}
          </Box>
        ) : null}
        {decodeError ? (
          <Typography variant="body2" color="error" sx={{ mt: 2 }}>
            {decodeError}
          </Typography>
        ) : null}
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={handleClose}>{t('common.close')}</Button>
      </DialogActions>
    </Dialog>
  )
}
