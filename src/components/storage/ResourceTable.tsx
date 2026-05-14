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
  ariaLabel?: string
}

export function ResourceTable({ resources, ariaLabel }: ResourceTableProps) {
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
}

function ResourceRow({ resource, locale }: ResourceRowProps) {
  const { t } = useTranslation()
  const displayName = getResourceDisplayName(resource)
  const typeLabel = getResourceTypeLabel(resource, t)
  const modifiedIso = getResourceModifiedIso(resource)
  const modified = modifiedIso ? formatRelativeTime(modifiedIso, locale) : ''

  return (
    <TableRow hover sx={storageStyles.resourceRow}>
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
