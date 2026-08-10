import { useMemo, useState, useEffect } from 'react'
import type { FuseOptionKey } from 'fuse.js'
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
  Button,
  Link
} from '@mui/material'
import {
  Timeline,
  TimelineItem,
  TimelineSeparator,
  TimelineDot,
  TimelineConnector,
  TimelineContent
} from '@mui/lab'
import { Link as RouterLink } from 'react-router'
import { useAuthStore } from '@/stores/authStore'
import type { WalletActivity } from '@/stores/storageManager'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { JsonHighlight } from '@/components/JsonHighlight'
import { MdClose, MdSearch } from 'react-icons/md'
import { formatRelativeTime } from '@/lib/formatRelativeTime'
import { historyStyles, infoBoxStyles } from '@/styles/appStyles'
import { credentialDetailStyles } from '@/styles/credentialStyles'
import { useTranslation } from 'react-i18next'
import {
  classifyActivity,
  credentialActivityInfo,
  type HistoryTab
} from '@/lib/historyActivity'
import { useSearch } from '@/hooks/useSearch'

type HistoryItem = { id: string; doc: WalletActivity }

// Module-level so it's referentially stable across renders -- it feeds
// `useSearch`'s memoized index, which is keyed on this array.
const HISTORY_SEARCH_KEYS: FuseOptionKey<HistoryItem>[] = [
  { name: 'doc.summary', weight: 0.7 },
  { name: 'doc.type', weight: 0.3 }
]

export function HistoryPage() {
  const { t, i18n } = useTranslation()
  const session = useAuthStore(state => state.session)
  const [historyItems, setHistoryItems] = useState<HistoryItem[]>([])
  const [loading, setLoading] = useState(true)

  const [tab, setTab] = useState<HistoryTab>('all')

  const [selectedItem, setSelectedItem] = useState<HistoryItem | null>(null)

  const sourceJson = useMemo(() => {
    if (!selectedItem) {
      return ''
    }
    return JSON.stringify(selectedItem.doc, null, 2)
  }, [selectedItem])

  // Single-credential activities (create/share/unshare) get a title link to
  // the credential; a deleted credential has nothing left to link to, so its
  // title renders as plain text. Every other activity (login, app revoke,
  // collection share) falls back to its plain `summary` line.
  function renderActivityLine(doc: WalletActivity) {
    const info = credentialActivityInfo(doc)
    if (!info) {
      return doc?.summary ?? doc?.type?.join(', ') ?? t('common.activity')
    }
    const titleText = info.title ?? info.cid
    const verbText = t(`history.credentialVerbs.${info.verb}`)
    return (
      <>
        {info.verb === 'deleted' ? (
          titleText
        ) : (
          <Link
            component={RouterLink}
            to={`/credential/${info.cid}`}
            underline="hover"
          >
            {titleText}
          </Link>
        )}{' '}
        {verbText}
      </>
    )
  }

  const {
    query,
    setQuery,
    results: searchedItems
  } = useSearch({ items: historyItems, keys: HISTORY_SEARCH_KEYS })

  // The tab counts describe the whole history, so they are keyed on it alone
  // and do not recompute per keystroke in the search box.
  const tabCounts = useMemo(() => {
    const counts: Record<HistoryTab, number> = {
      all: historyItems.length,
      credentials: 0,
      login: 0,
      applications: 0
    }
    for (const item of historyItems) {
      const category = classifyActivity(item.doc)
      if (category !== 'other') {
        counts[category] += 1
      }
    }
    return counts
  }, [historyItems])

  const filteredItems = useMemo(
    () =>
      searchedItems.filter(item => {
        const category = classifyActivity(item.doc)
        return tab === 'all' || category === tab
      }),
    [searchedItems, tab]
  )

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
                      {renderActivityLine(doc)}
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
        open={selectedItem !== null}
        onClose={() => setSelectedItem(null)}
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
            onClick={() => setSelectedItem(null)}
            size="small"
            aria-label={t('common.close')}
          >
            <MdClose />
          </IconButton>
        </DialogTitle>

        <DialogContent sx={infoBoxStyles.content}>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {selectedItem?.doc?.summary && (
              <Typography variant="caption" color="text.secondary">
                {selectedItem.doc.summary}
              </Typography>
            )}
            <JsonHighlight
              code={sourceJson}
              sx={credentialDetailStyles.codeBlock}
            />
          </Box>
        </DialogContent>
      </Dialog>
    </DashboardLayout>
  )
}
