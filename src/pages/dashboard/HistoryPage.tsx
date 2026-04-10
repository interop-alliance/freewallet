import { useState, useEffect } from 'react'
import Typography from '@mui/material/Typography'
import Timeline from '@mui/lab/Timeline'
import TimelineItem from '@mui/lab/TimelineItem'
import TimelineSeparator from '@mui/lab/TimelineSeparator'
import TimelineConnector from '@mui/lab/TimelineConnector'
import TimelineContent from '@mui/lab/TimelineContent'
import TimelineDot from '@mui/lab/TimelineDot'
import { useAuthStore } from '@/stores/authStore'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'

export function HistoryPage() {
  const session = useAuthStore(state => state.session)
  const [historyItems, setHistoryItems] = useState<
    Array<{ id: string; doc: any }>
  >([])
  const [loading, setLoading] = useState(true)

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
    <DashboardLayout title="History">
      {loading ? (
        <LoadingSpinner />
      ) : historyItems.length === 0 ? (
        <Typography color="text.secondary">No history items found.</Typography>
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
                  {doc?.summary ?? doc?.type?.join(', ') ?? 'Activity'}
                </Typography>
                {doc?.created && (
                  <Typography variant="caption" color="text.secondary">
                    {new Date(doc.created).toLocaleString()}
                  </Typography>
                )}
              </TimelineContent>
            </TimelineItem>
          ))}
        </Timeline>
      )}
    </DashboardLayout>
  )
}
