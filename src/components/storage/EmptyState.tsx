import type { ReactNode } from 'react'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import { storageStyles } from '@/styles/appStyles'

/**
 * Reusable empty state for storage views (no collections, empty folder, etc.)
 */
export function StorageEmptyState({
  icon,
  title,
  description
}: {
  icon: ReactNode
  title: string
  description?: string
}) {
  return (
    <Box sx={storageStyles.emptyState}>
      <Box sx={storageStyles.emptyStateIcon}>{icon}</Box>
      <Typography variant="h6" sx={storageStyles.emptyStateTitle}>
        {title}
      </Typography>
      {description && (
        <Typography variant="body2" sx={storageStyles.emptyStateDescription}>
          {description}
        </Typography>
      )}
    </Box>
  )
}
