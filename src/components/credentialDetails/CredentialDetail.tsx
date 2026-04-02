import { useMemo, useState } from 'react'
import {
  Box,
  Typography,
  Stack,
  Paper,
  Divider,
  Link,
  Collapse,
  Button,
  IconButton
} from '@mui/material'
import { MdDeleteOutline } from 'react-icons/md'
import { reset as microlightReset } from 'microlight'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { getDisplayFields } from '@/lib/credentialDisplayFields'
import { formatDate } from '@/lib/formatDate'
import { getProofCreatedIso } from '@/lib/getProofCreatedIso'
import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import { IssuerInfo } from '@/components/credentialDetails/IssuerInfo'
import {
  InfoBlock,
  SectionHeader
} from '@/components/credentialDetails/InfoBlock'
import {
  credentialDetailStyles,
  credentialDetailCardStyles as sx
} from '@/styles/credentialStyles'
import type { IAlignment } from '@digitalcredentials/ssi'

export function CredentialDetail({
  vc,
  onDelete
}: {
  vc: IVerifiableCredential
  onDelete?: () => void
}) {
  const fields = useMemo(() => getDisplayFields(vc), [vc])
  const signatureCreatedIso = useMemo(() => getProofCreatedIso(vc), [vc])
  const [showRaw, setShowRaw] = useState(false)
  const rawJson = useMemo(() => JSON.stringify(vc, null, 2), [vc])

  return (
    <Paper variant="outlined" sx={sx.card}>
      {onDelete && (
        <IconButton
          size="small"
          onClick={onDelete}
          aria-label="Delete credential"
          sx={sx.cardDeleteIcon}
        >
          <MdDeleteOutline size={24} />
        </IconButton>
      )}
      {/* ── Top section: achievement image + name + type ── */}
      <Box
        sx={{ ...sx.topCard, ...(onDelete ? { pr: { xs: 5, md: 6 } } : {}) }}
      >
        <Box sx={sx.achievementRow}>
          {fields.achievementImage && (
            <Box
              component="img"
              src={fields.achievementImage}
              alt=""
              sx={sx.achievementImage}
            />
          )}
          <Box>
            <Typography variant="h5" component="h2" sx={sx.credentialName}>
              {fields.credentialName}
            </Typography>
            {fields.achievementType && (
              <Typography
                variant="body2"
                color="text.secondary"
                sx={sx.achievementType}
              >
                Achievement Type: {fields.achievementType}
              </Typography>
            )}
          </Box>
        </Box>
      </Box>

      {/* ── Main area: two-column layout ── */}
      <Box sx={sx.mainCard}>
        {/* ── Secondary column: issuer + dates ── */}
        <Box sx={sx.secondaryColumn}>
          <Stack spacing={3}>
            <IssuerInfo issuer={vc.issuer} />

            <Box>
              {signatureCreatedIso && (
                <InfoBlock
                  header="Signature date"
                  value={formatDate({ isoDate: signatureCreatedIso })}
                />
              )}
              <Box sx={{ mt: signatureCreatedIso ? 2 : 0 }}>
                <InfoBlock
                  header="Expiration Date"
                  value={
                    fields.expirationDate
                      ? formatDate({ isoDate: fields.expirationDate })
                      : 'N/A'
                  }
                />
              </Box>
            </Box>
          </Stack>
        </Box>

        <Divider orientation="vertical" flexItem sx={sx.dividerVertical} />
        <Divider sx={sx.dividerHorizontal} />

        {/* ── Primary column: issued-to, description, criteria, alignments ── */}
        <Box sx={sx.primaryColumn}>
          {fields.issuedTo && (
            <InfoBlock header="Issued To" value={fields.issuedTo} />
          )}

          {fields.credentialDescription && (
            <InfoBlock
              header="Description"
              value={fields.credentialDescription}
            />
          )}

          {fields.criteria && (
            <Box>
              <SectionHeader>Criteria</SectionHeader>
              <Box sx={sx.markdownBody}>
                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                  {fields.criteria}
                </ReactMarkdown>
              </Box>
            </Box>
          )}

          {fields.alignments.length > 0 && (
            <Box>
              <SectionHeader>Alignments</SectionHeader>
              <Stack spacing={1}>
                {fields.alignments.map((field: IAlignment, i: number) => (
                  <Box key={i}>
                    <Typography variant="body2" sx={sx.alignmentName}>
                      {field.targetName}
                    </Typography>
                    {field.targetUrl && (
                      <Link
                        href={field.targetUrl}
                        target="_blank"
                        rel="noopener"
                        variant="caption"
                      >
                        {field.targetUrl}
                      </Link>
                    )}
                    {field.targetDescription && (
                      <Typography variant="body2" color="text.secondary">
                        {field.targetDescription}
                      </Typography>
                    )}
                  </Box>
                ))}
              </Stack>
            </Box>
          )}
        </Box>
      </Box>

      {/* ── Collapsible raw JSON ── */}
      <Divider />
      <Box sx={sx.rawToggleWrapper}>
        <Button
          size="small"
          variant="text"
          onClick={() => {
            setShowRaw(prev => !prev)
            if (!showRaw) {
              requestAnimationFrame(() => microlightReset())
            }
          }}
          sx={sx.rawToggle}
        >
          {showRaw ? 'Hide JSON' : 'View Source'}
        </Button>
        <Collapse in={showRaw} unmountOnExit>
          <Box
            component="pre"
            className="microlight"
            sx={credentialDetailStyles.codeBlock}
          >
            {rawJson}
          </Box>
        </Collapse>
      </Box>
    </Paper>
  )
}
