import { useMemo, useState, useEffect } from 'react'
import {
  Box,
  Typography,
  Tabs,
  Tab,
  TextField,
  Dialog,
  DialogTitle,
  DialogContent,
  IconButton,
  Button
} from '@mui/material'
import {
  Timeline,
  TimelineItem,
  TimelineSeparator,
  TimelineDot,
  TimelineConnector,
  TimelineContent
} from '@mui/lab'
import { useAuthStore } from '@/stores/authStore'
import type { WalletActivity } from '@/stores/storageManager'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { MdClose, MdSearch } from 'react-icons/md'
import { formatRelativeTime } from '@/lib/formatRelativeTime'
import { historyStyles, infoBoxStyles } from '@/styles/appStyles'
import { credentialDetailStyles } from '@/styles/credentialStyles'
import { useTranslation } from 'react-i18next'
import { classifyActivity, type HistoryTab } from '@/lib/historyActivity'

export function HistoryPage() {
  const { t, i18n } = useTranslation()
  const session = useAuthStore(state => state.session)
  const [historyItems, setHistoryItems] = useState<
    Array<{ id: string; doc: WalletActivity }>
  >([])
  const [loading, setLoading] = useState(true)

  const [tab, setTab] = useState<HistoryTab>('all')
  const [query, setQuery] = useState('')

  const [sourceOpen, setSourceOpen] = useState(false)
  const [selectedItem, setSelectedItem] = useState<{
    id: string
    doc: WalletActivity
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

  const normalizedQuery = query.trim().toLowerCase()

  const { tabCounts, filteredItems } = useMemo(() => {
    const counts: Record<HistoryTab, number> = {
      all: historyItems.length,
      credentials: 0,
      login: 0,
      applications: 0
    }
    const filtered: Array<{ id: string; doc: WalletActivity }> = []
    for (const item of historyItems) {
      const category = classifyActivity(item.doc)
      if (category !== 'other') {
        counts[category] += 1
      }
      if (tab !== 'all' && category !== tab) {
        continue
      }
      if (
        normalizedQuery &&
        !item.doc.summary?.toLowerCase().includes(normalizedQuery)
      ) {
        continue
      }
      filtered.push(item)
    }
    return { tabCounts: counts, filteredItems: filtered }
  }, [historyItems, tab, normalizedQuery])

  useEffect(() => {
    let cancelled = false

    async function initialLoad() {
      if (!session?.storage) {
        return
      }
      const items = await session.storage.listHistoryItems()
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
        <>
          <Box sx={historyStyles.toolbar}>
            <Tabs
              value={tab}
              onChange={(_event, value: HistoryTab) => setTab(value)}
              sx={historyStyles.tabs}
            >
              <Tab
                value="all"
                label={`${t('history.tabs.all')} (${tabCounts.all})`}
              />
              <Tab
                value="credentials"
                label={`${t('history.tabs.credentials')} (${tabCounts.credentials})`}
              />
              <Tab
                value="login"
                label={`${t('history.tabs.login')} (${tabCounts.login})`}
              />
              <Tab
                value="applications"
                label={`${t('history.tabs.applications')} (${tabCounts.applications})`}
              />
            </Tabs>
            <TextField
              size="small"
              value={query}
              onChange={event => setQuery(event.target.value)}
              placeholder={t('history.searchPlaceholder')}
              sx={historyStyles.searchField}
              slotProps={{
                input: {
                  startAdornment: (
                    <Box
                      component="span"
                      sx={{ display: 'flex', color: 'text.secondary', mr: 1 }}
                    >
                      <MdSearch />
                    </Box>
                  )
                }
              }}
            />
          </Box>

          {filteredItems.length === 0 ? (
            <Typography color="text.secondary" sx={{ mt: 3 }}>
              {t('history.noResults')}
            </Typography>
          ) : (
            <Timeline sx={{ p: 0, m: 0, mt: 3 }}>
              {filteredItems.map(({ id, doc }, index) => (
                <TimelineItem
                  key={id}
                  sx={{ '&::before': { display: 'none' } }}
                >
                  <TimelineSeparator>
                    <TimelineDot />
                    {index < filteredItems.length - 1 && <TimelineConnector />}
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
        </>
      )}

      <Dialog
        open={sourceOpen}
        onClose={() => setSourceOpen(false)}
        maxWidth="md"
        fullWidth
        scroll="paper"
        aria-labelledby="history-source-dialog-title"
        slotProps={{ paper: { sx: infoBoxStyles.paper } }}
      >
        <DialogTitle
          component="h6"
          id="history-source-dialog-title"
          sx={infoBoxStyles.header}
        >
          <Box component="span" sx={infoBoxStyles.title}>
            {t('history.dialogTitle')}
          </Box>
          <IconButton
            onClick={() => setSourceOpen(false)}
            size="small"
            aria-label={t('common.close')}
          >
            <MdClose />
          </IconButton>
        </DialogTitle>

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
