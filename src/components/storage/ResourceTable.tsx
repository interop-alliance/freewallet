import {
  Box,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography
} from '@mui/material'
import { MdInsertDriveFile } from 'react-icons/md'
import { useTranslation } from 'react-i18next'
import type { KeyboardEvent } from 'react'
import type { StorageResource } from '@/lib/storage'
import { storageStyles } from '@/styles/appStyles'
import { formatRelativeTime } from '@/lib/formatRelativeTime'
import {
  getResourceDisplayName,
  getResourceModifiedIso,
  getResourceTypeLabel
} from './displayUtils'

interface ResourceTableProps {
  resources: StorageResource[]
  onResourceOpen: (resource: StorageResource) => void
  selectedResourceId?: string | null
  ariaLabel?: string
}

export function ResourceTable({
  resources,
  onResourceOpen,
  selectedResourceId,
  ariaLabel
}: ResourceTableProps) {
  const { t, i18n } = useTranslation()

  return (
    <TableContainer sx={storageStyles.resourceTableContainer}>
      <Table
        size="small"
        aria-label={ariaLabel ?? t('storage.resourcesTableLabel')}
        sx={storageStyles.resourceTable}
      >
        <TableHead>
          <TableRow>
            <TableCell sx={storageStyles.resourceHeaderCell}>
              {t('storage.columns.name')}
            </TableCell>
            <TableCell sx={storageStyles.resourceHeaderCell}>
              {t('storage.columns.type')}
            </TableCell>
            <TableCell sx={storageStyles.resourceHeaderCell}>
              {t('storage.columns.modified')}
            </TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {resources.map(resource => (
            <ResourceRow
              key={resource.id}
              resource={resource}
              locale={i18n.language}
              selected={selectedResourceId === resource.id}
              onOpen={() => {
                onResourceOpen(resource)
              }}
            />
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  )
}

interface ResourceRowProps {
  resource: StorageResource
  locale: string
  selected: boolean
  onOpen: () => void
}

function ResourceRow({ resource, locale, selected, onOpen }: ResourceRowProps) {
  const { t } = useTranslation()
  const displayName = getResourceDisplayName(resource)
  const typeLabel = getResourceTypeLabel(resource, t)
  const modifiedIso = getResourceModifiedIso(resource)
  const modified = modifiedIso ? formatRelativeTime(modifiedIso, locale) : ''

  return (
    <TableRow
      hover
      selected={selected}
      sx={{
        ...storageStyles.resourceRow,
        cursor: 'pointer'
      }}
      onClick={() => {
        onOpen()
      }}
      tabIndex={0}
      role="button"
      onKeyDown={(e: KeyboardEvent) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onOpen()
        }
      }}
    >
      <TableCell sx={storageStyles.resourceNameCell}>
        <Box sx={storageStyles.resourceNameInner}>
          <Box sx={storageStyles.resourceFileIcon} aria-hidden>
            <MdInsertDriveFile />
          </Box>
          <Typography variant="body2" sx={storageStyles.resourceNameText}>
            {displayName}
          </Typography>
        </Box>
      </TableCell>
      <TableCell sx={storageStyles.resourceTypeCell}>
        <Chip
          label={typeLabel}
          size="small"
          variant="outlined"
          sx={storageStyles.resourceTypeChip}
        />
      </TableCell>
      <TableCell sx={storageStyles.resourceModifiedCell}>
        <Typography variant="body2" color="text.secondary">
          {modified || t('common.na')}
        </Typography>
      </TableCell>
    </TableRow>
  )
}
