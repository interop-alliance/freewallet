import { lazy, Suspense, useCallback, useState, type ReactNode } from 'react'
import Box from '@mui/material/Box'
import Dialog from '@mui/material/Dialog'
import DialogContent from '@mui/material/DialogContent'
import IconButton from '@mui/material/IconButton'
import Typography from '@mui/material/Typography'
import { MdClose } from 'react-icons/md'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { infoBoxStyles } from '@/styles/appStyles'
import { InfoBox, type InfoBoxOptions } from '@/context/infoBoxStore'
import { useTranslation } from 'react-i18next'

// Lazily loaded: DocContent pulls in the react-markdown/remark stack, which
// would otherwise land in the eager entry chunk (this provider wraps the app).
const DocContent = lazy(() =>
  import('@/components/DocContent').then(mod => ({ default: mod.DocContent }))
)

export function InfoBoxProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [options, setOptions] = useState<InfoBoxOptions | null>(null)

  const displayInfoBox = useCallback((opts: InfoBoxOptions) => {
    const slug = opts.docUrl.trim()
    setOptions({ ...opts, docUrl: slug })
    setOpen(true)
  }, [])

  const handleClose = () => setOpen(false)

  return (
    <InfoBox.Provider value={{ displayInfoBox }}>
      {children}
      <Dialog
        open={open}
        onClose={handleClose}
        maxWidth="md"
        fullWidth
        scroll="paper"
        slotProps={{ paper: { sx: infoBoxStyles.paper } }}
      >
        <Box sx={infoBoxStyles.header}>
          {options?.title ? (
            <Typography variant="h6" sx={infoBoxStyles.title}>
              {options.title}
            </Typography>
          ) : (
            <Box sx={infoBoxStyles.spacer} />
          )}
          <IconButton
            onClick={handleClose}
            size="small"
            aria-label={t('common.close')}
            autoFocus
          >
            <MdClose />
          </IconButton>
        </Box>

        <DialogContent sx={infoBoxStyles.content}>
          {options && (
            <Suspense fallback={<LoadingSpinner />}>
              <DocContent key={options.docUrl} fileName={options.docUrl} />
            </Suspense>
          )}
        </DialogContent>
      </Dialog>
    </InfoBox.Provider>
  )
}
