/**
 * Collapsible raw-source viewer for a CHAPI consent screen. Renders a
 * "View request source code" text toggle (chevron rotates on expand) that
 * reveals the incoming CHAPI request as a syntax-highlighted JSON code block.
 * Shared by the get, store, and App Connect consent screens; renders nothing
 * when no request payload is available.
 */
import { useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Collapse from '@mui/material/Collapse'
import { MdChevronRight, MdExpandMore } from 'react-icons/md'
import { useTranslation } from 'react-i18next'
import { JsonHighlight } from '@/components/JsonHighlight'
import { chapiStyles } from '@/styles/appStyles'

export function RequestSourcePanel({ source }: { source: unknown }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)

  if (source == null) {
    return null
  }
  return (
    <Box>
      <Button
        size="small"
        variant="text"
        startIcon={open ? <MdExpandMore /> : <MdChevronRight />}
        onClick={() => setOpen(prev => !prev)}
        sx={chapiStyles.sourceToggle}
      >
        {t(open ? 'chapi.hideRequestSource' : 'chapi.viewRequestSource')}
      </Button>
      <Collapse in={open} unmountOnExit>
        <JsonHighlight
          code={JSON.stringify(source, null, 2)}
          sx={chapiStyles.sourceCodeBlock}
        />
      </Collapse>
    </Box>
  )
}
