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
  Box,
  FormControlLabel,
  Switch
} from '@mui/material'
import QrScanner from 'qr-scanner'
import { useTranslation } from 'react-i18next'
import {
  resolveWalletInput,
  type WalletInputOutcome
} from '@/lib/resolveWalletInput'
import { resolveCredentialsInputErrorMessage } from '@/lib/resolveCredentialsInputErrorMessage'
import {
  scanCredentialQrStyles,
  scanCredentialQrVideoStyle
} from '@/styles/scanCredentialQrStyles'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:scan-qr')

/**
 * Formats one error for the on-page diagnostics list: name and message,
 * plus the first stack frames, so a phone browser with no console still
 * shows what the scanner hit.
 */
function describeError(err: unknown): string {
  if (err instanceof Error) {
    const frames = (err.stack ?? '')
      .split('\n')
      .slice(1, 4)
      .map(line => line.trim())
      .join('\n  ')
    return `${err.name}: ${err.message}${frames ? `\n  ${frames}` : ''}`
  }
  return String(err)
}

/**
 * The library picks its decode engine once, at construction: the browser's
 * native `BarcodeDetector` when present (Chrome on Android), its jsQR Web
 * Worker otherwise. The flag is a private static, so forcing the worker is
 * reached through a cast. A diagnostic, not a product setting.
 */
function setForceJsDecoder(force: boolean): void {
  ;(
    QrScanner as unknown as { _disableBarcodeDetector: boolean }
  )._disableBarcodeDetector = force
}

export function ScanCredentialQrDialog({
  open,
  onClose,
  onResolved
}: {
  open: boolean
  onClose: () => void
  /**
   * Same routing as Add Credential: credentials go to the review screen
   * before storing, an interaction URL to the request page.
   */
  onResolved: (outcome: WalletInputOutcome) => void
}) {
  const { t } = useTranslation()
  const scannerRef = useRef<QrScanner | null>(null)
  const [decodeError, setDecodeError] = useState<string | null>(null)
  const [startingCamera, setStartingCamera] = useState(false)
  const [cameraBlocked, setCameraBlocked] = useState(false)
  const [forceJsDecoder, setForceJsDecoder_] = useState(true)
  const [diagnostics, setDiagnostics] = useState<string[]>([])

  const addDiagnostic = useCallback((line: string) => {
    setDiagnostics(prev => [...prev, line])
  }, [])

  const reportError = useCallback(
    (label: string, err: unknown) => {
      log.error(label, { err })
      addDiagnostic(`${label}\n${describeError(err)}`)
    },
    [addDiagnostic]
  )

  const destroyScanner = useCallback(() => {
    scannerRef.current?.destroy()
    scannerRef.current = null
  }, [])

  const onScanFail = useCallback(
    (error: Error | string) => {
      const msg = typeof error === 'string' ? error : error.message
      if (msg !== QrScanner.NO_QR_CODE_FOUND) {
        reportError('Decode engine error', error)
        setDecodeError(t('dashboard.scanQr.scanEngineError'))
        destroyScanner()
      }
    },
    [destroyScanner, reportError, t]
  )

  const onScanSuccess = useCallback(
    async (result: string | { data: string }) => {
      const sc = scannerRef.current
      if (!sc) {
        return
      }
      const data = typeof result === 'string' ? result : result.data
      try {
        sc.stop()
        onResolved(await resolveWalletInput(data))
      } catch (err) {
        reportError('Scanned payload refused', err)
        setDecodeError(
          resolveCredentialsInputErrorMessage(err, t, { trimmed: data })
        )
        sc.start().catch(restartErr => {
          reportError('Camera restart failed', restartErr)
        })
      }
    },
    [onResolved, reportError, t]
  )

  const handleClose = useCallback(() => {
    setDecodeError(null)
    setStartingCamera(false)
    setCameraBlocked(false)
    setDiagnostics([])
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
      setDiagnostics([])

      const nativeDetector = 'BarcodeDetector' in window
      const engine =
        nativeDetector && !forceJsDecoder
          ? 'native BarcodeDetector'
          : 'jsQR worker'
      const environment = {
        engine,
        nativeDetector,
        forceJsDecoder,
        mediaDevices: typeof navigator.mediaDevices !== 'undefined',
        userAgent: navigator.userAgent
      }
      log.info('Starting the QR scanner', environment)
      addDiagnostic(
        `engine: ${engine} (BarcodeDetector in window: ${nativeDetector}, ` +
          `mediaDevices: ${environment.mediaDevices})\n${navigator.userAgent}`
      )

      try {
        setForceJsDecoder(forceJsDecoder)
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
          .then(async () => {
            addDiagnostic(
              `camera started: ${video.videoWidth}x${video.videoHeight}`
            )
            try {
              const cameras = await QrScanner.listCameras(true)
              const labels = cameras.map(cam => cam.label || cam.id)
              log.info('Cameras', { cameras: labels })
              addDiagnostic(`cameras: ${labels.join(', ') || '(none)'}`)
            } catch (err) {
              reportError('Camera listing failed', err)
            }
          })
          .catch(err => {
            reportError('Camera start failed', err)
            setCameraBlocked(true)
            setDecodeError(t('dashboard.scanQr.cameraError'))
          })
          .finally(() => {
            setStartingCamera(false)
          })
      } catch (err) {
        reportError('Scanner construction failed', err)
        setStartingCamera(false)
        setCameraBlocked(true)
        setDecodeError(t('dashboard.scanQr.cameraError'))
      }
    },
    [
      destroyScanner,
      open,
      forceJsDecoder,
      onScanFail,
      onScanSuccess,
      addDiagnostic,
      reportError,
      t
    ]
  )

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ pb: 1 }}>{t('dashboard.scanQr.title')}</DialogTitle>
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
            {/*
              The scanner inserts its highlight overlay as a sibling of the
              video, so the video gets a wrapper of its own and shares no
              parent with React-managed children (the spinner below).
            */}
            <div style={scanCredentialQrStyles.videoWrapper}>
              <video
                // The ref callback's identity changes with the decoder
                // toggle, which React honours by detaching and re-attaching,
                // so the toggle rebuilds the scanner on the chosen engine.
                ref={attachVideoRef}
                muted
                playsInline
                style={scanCredentialQrVideoStyle}
              />
            </div>
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
        <FormControlLabel
          sx={{ mt: 1 }}
          control={
            <Switch
              size="small"
              checked={forceJsDecoder}
              onChange={event => setForceJsDecoder_(event.target.checked)}
            />
          }
          label={
            <Typography variant="body2">
              {t('dashboard.scanQr.forceJsDecoder')}
            </Typography>
          }
        />
        {diagnostics.length > 0 ? (
          <Box sx={{ mt: 1 }}>
            <Typography variant="caption" color="text.secondary">
              {t('dashboard.scanQr.diagnosticsTitle')}
            </Typography>
            <Box component="pre" sx={scanCredentialQrStyles.diagnostics}>
              {diagnostics.join('\n\n')}
            </Box>
          </Box>
        ) : null}
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={handleClose}>{t('common.close')}</Button>
      </DialogActions>
    </Dialog>
  )
}
