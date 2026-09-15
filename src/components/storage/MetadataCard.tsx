/**
 * The storage browser's metadata card: a collapsed accordion that reads a
 * Resource's or a Collection's `/meta` document the first time it is expanded
 * and renders the server-managed members as labeled rows, with a toggle for
 * the raw metadata document beneath them. The page's own load path never pays
 * for this read -- nothing is fetched until the user opens the card.
 *
 * A server without metadata support (`NotImplementedError`) and a `null`
 * read are the same empty state here, not an error. was-client resolves
 * null on a 404, which the server also answers for a target this session
 * may not read (an expired generation delegation, a read outside the
 * grant), so the null branch is logged.
 *
 * The encrypted caption over `custom` is resolved at expand time, beside the
 * document, so it reflects the collection's governing log rather than a
 * host-served member read at page load.
 */
import { useCallback, useRef, useState } from 'react'
import type { SyntheticEvent } from 'react'
import Accordion from '@mui/material/Accordion'
import AccordionDetails from '@mui/material/AccordionDetails'
import AccordionSummary from '@mui/material/AccordionSummary'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { MdExpandMore } from 'react-icons/md'
import { useTranslation } from 'react-i18next'
import { errorNameOf } from '@interop/wallet-core/menders'
import { JsonHighlight } from '@/components/JsonHighlight'
import { credentialDetailStyles } from '@/styles/credentialStyles'
import { metadataRows } from '@/components/storage/metadataRows'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:storage')

/**
 * Renders the metadata card.
 *
 * @param options {object}
 * @param options.fetchMeta {Function}   reads the `/meta` document (null on
 *   a 404) beside whether the collection is encrypted, which decides how
 *   `custom` is labeled (it is stored as an opaque envelope there, and this
 *   card never decrypts)
 * @param options.fieldOrder {string[]}   the known members, in display order
 * @returns {JSX.Element}
 */
export function MetadataCard({
  fetchMeta,
  fieldOrder
}: {
  fetchMeta: () => Promise<{
    meta: Record<string, unknown> | null
    encrypted: boolean
  }>
  fieldOrder: string[]
}) {
  const { t, i18n } = useTranslation()
  const started = useRef(false)
  const [showSource, setShowSource] = useState(false)
  const [status, setStatus] = useState<'idle' | 'loading' | 'ready' | 'error'>(
    'idle'
  )
  const [meta, setMeta] = useState<Record<string, unknown> | null>(null)
  const [encrypted, setEncrypted] = useState(false)

  const handleChange = useCallback(
    (_event: SyntheticEvent, isExpanded: boolean) => {
      if (!isExpanded || started.current) {
        return
      }
      started.current = true
      setStatus('loading')
      void (async () => {
        try {
          const read = await fetchMeta()
          if (read.meta === null) {
            log.warn('Metadata read resolved null (missing or not visible)')
          }
          setMeta(read.meta)
          setEncrypted(read.encrypted)
          setStatus('ready')
        } catch (err: unknown) {
          if (errorNameOf(err) === 'NotImplementedError') {
            setMeta(null)
            setStatus('ready')
            return
          }
          log.error('Failed to load metadata', { err })
          // Let the next expand retry.
          started.current = false
          setStatus('error')
        }
      })()
    },
    [fetchMeta]
  )

  const rows = meta
    ? metadataRows({ meta, fieldOrder, locale: i18n.language })
    : []
  const custom = meta?.custom
  const hasCustom =
    custom !== null &&
    custom !== undefined &&
    (typeof custom !== 'object' || Object.keys(custom).length > 0)

  return (
    <Accordion
      variant="outlined"
      disableGutters
      onChange={handleChange}
      sx={{ mb: 2 }}
    >
      <AccordionSummary expandIcon={<MdExpandMore />}>
        <Typography variant="subtitle1">{t('storage.meta.title')}</Typography>
      </AccordionSummary>
      <AccordionDetails>
        {status === 'loading' && (
          <Typography variant="body2" color="text.secondary">
            {t('storage.meta.loading')}
          </Typography>
        )}

        {status === 'error' && (
          <Typography variant="body2" color="error">
            {t('storage.meta.error')}
          </Typography>
        )}

        {status === 'ready' && rows.length === 0 && !hasCustom && (
          <Typography variant="body2" color="text.secondary">
            {t('storage.meta.empty')}
          </Typography>
        )}

        {status === 'ready' && (rows.length > 0 || hasCustom) && (
          <Stack spacing={1}>
            {rows.map(row => (
              <Stack
                key={row.key}
                direction={{ xs: 'column', sm: 'row' }}
                spacing={{ xs: 0, sm: 2 }}
              >
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{ minWidth: 180 }}
                >
                  {t(`storage.meta.fields.${row.key}`, {
                    defaultValue: row.key
                  })}
                </Typography>
                <Typography variant="body2" sx={{ wordBreak: 'break-word' }}>
                  {row.value}
                </Typography>
              </Stack>
            ))}

            {hasCustom && (
              <Box>
                <Typography variant="body2" color="text.secondary">
                  {encrypted
                    ? t('storage.meta.customEncrypted')
                    : t('storage.meta.custom')}
                </Typography>
                <JsonHighlight
                  code={JSON.stringify(custom, null, 2)}
                  sx={credentialDetailStyles.codeBlock}
                />
              </Box>
            )}

            <Box>
              <Button
                size="small"
                variant="text"
                onClick={() => setShowSource(current => !current)}
              >
                {showSource
                  ? t('storage.meta.hideSource')
                  : t('storage.meta.viewSource')}
              </Button>
              {showSource && (
                <JsonHighlight
                  code={JSON.stringify(meta, null, 2)}
                  sx={credentialDetailStyles.codeBlock}
                />
              )}
            </Box>
          </Stack>
        )}
      </AccordionDetails>
    </Accordion>
  )
}
