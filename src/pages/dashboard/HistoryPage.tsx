import { useMemo, useState, useEffect } from 'react'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import Timeline from '@mui/lab/Timeline'
import TimelineItem from '@mui/lab/TimelineItem'
import TimelineSeparator from '@mui/lab/TimelineSeparator'
import TimelineConnector from '@mui/lab/TimelineConnector'
import TimelineContent from '@mui/lab/TimelineContent'
import TimelineDot from '@mui/lab/TimelineDot'
import Dialog from '@mui/material/Dialog'
import DialogContent from '@mui/material/DialogContent'
import IconButton from '@mui/material/IconButton'
import { useAuthStore } from '@/stores/authStore'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import Button from '@mui/material/Button'
import { MdClose } from 'react-icons/md'
import { formatRelativeTime } from '@/lib/formatRelativeTime'
import { historyStyles, infoBoxStyles } from '@/styles/appStyles'
import { credentialDetailStyles } from '@/styles/credentialStyles'
import { useTranslation } from 'react-i18next'

export function HistoryPage() {
  const { t, i18n } = useTranslation()
  const session = useAuthStore(state => state.session)
  const [historyItems, setHistoryItems] = useState<
    Array<{ id: string; doc: any }>
  >([])
  const [loading, setLoading] = useState(true)

  const [sourceOpen, setSourceOpen] = useState(false)
  const [selectedItem, setSelectedItem] = useState<{
    id: string
    doc: Record<string, unknown>
  } | null>(null)

  const sourceJson = useMemo(() => {
    if (!selectedItem) {
      return ''
    }
    return JSON.stringify(selectedItem.doc, null, 2)
  }, [selectedItem])

  const selectedSummary = useMemo(() => {
    return selectedItem?.doc?.summary ?? ''
  }, [selectedItem])

  // const loadHistory = useCallback(async () => {
  //   if (!session?.storage) {
  //     throw new Error('Storage not initialized')
  //   }
  //   const items = await session.storage.remoteStore!.listHistoryItems()
  //   setHistoryItems(items)
  // }, [session])

  useEffect(() => {
    let cancelled = false

    async function initialLoad() {
      if (!session?.storage) {
        return
      }
      const items = await session.storage.remoteStore!.listHistoryItems()
      if (!cancelled) {
        setHistoryItems(items)
        setLoading(false)
      }
    }
    initialLoad()

    return () => {
      cancelled = true
    }
  }, [session])

  return (
    <DashboardLayout title={t('history.title')}>
      {loading ? (
        <LoadingSpinner />
      ) : historyItems.length === 0 ? (
        <Typography color="text.secondary">{t('history.empty')}</Typography>
      ) : (
        <Timeline sx={{ p: 0, m: 0, mt: 3 }}>
          {historyItems.map(({ id, doc }, index) => (
            <TimelineItem key={id} sx={{ '&::before': { display: 'none' } }}>
              <TimelineSeparator>
                <TimelineDot />
                {index < historyItems.length - 1 && <TimelineConnector />}
              </TimelineSeparator>
              <TimelineContent>
                <Typography variant="body1">
                  {doc?.summary ??
                    doc?.type?.join(', ') ??
                    t('common.activity')}
                </Typography>
                {doc?.created && (
                  <Box sx={historyStyles.timestampRow}>
                    <Typography variant="caption" color="text.secondary">
                      {formatRelativeTime(doc.created, i18n.language)}
                    </Typography>
                    <Button
                      size="small"
                      variant="text"
                      color="secondary"
                      sx={historyStyles.viewSourceButton}
                      onClick={() => {
                        setSelectedItem({ id, doc })
                        setSourceOpen(true)
                      }}
                    >
                      {t('history.viewSource')}
                    </Button>
                  </Box>
                )}
              </TimelineContent>
            </TimelineItem>
          ))}
        </Timeline>
      )}

      <Dialog
        open={sourceOpen}
        onClose={() => setSourceOpen(false)}
        maxWidth="md"
        fullWidth
        scroll="paper"
        slotProps={{ paper: { sx: infoBoxStyles.paper } }}
      >
        <Box sx={infoBoxStyles.header}>
          <Typography variant="h6" sx={infoBoxStyles.title}>
            {t('history.dialogTitle')}
          </Typography>
          <IconButton
            onClick={() => setSourceOpen(false)}
            size="small"
            aria-label={t('common.close')}
          >
            <MdClose />
          </IconButton>
        </Box>

        <DialogContent sx={infoBoxStyles.content}>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {selectedSummary && (
              <Typography variant="caption" color="text.secondary">
                {selectedSummary as string}
              </Typography>
            )}
            <Box component="pre" sx={credentialDetailStyles.codeBlock}>
              {sourceJson}
            </Box>
          </Box>
        </DialogContent>
      </Dialog>
    </DashboardLayout>
  )
}
