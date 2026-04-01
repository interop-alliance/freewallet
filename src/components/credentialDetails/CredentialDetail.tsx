import { useMemo, useState } from 'react'
import {
  Box,
  Typography,
  Stack,
  Paper,
  Divider,
  Link,
  Collapse,
  Button
} from '@mui/material'
import { reset as microlightReset } from 'microlight'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { getDisplayFields } from '@/lib/credentialDisplayFields'
import { formatDate } from '@/lib/formatDate'
import type { AlignmentItem } from '@/types/credential'
import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import { IssuerInfo } from '@/components/credentialDetails/IssuerInfo'
import {
  InfoBlock,
  SectionHeader
} from '@/components/credentialDetails/InfoBlock'
import { credentialDetailStyles } from '@/styles/appStyles'
import { credentialCardStyles as sx } from '@/styles/credentialStyles'

interface CredentialDetailProps {
  vc: IVerifiableCredential
}

export function CredentialDetail({ vc }: CredentialDetailProps) {
  const fields = useMemo(() => getDisplayFields(vc), [vc])
  const [showRaw, setShowRaw] = useState(false)
  const rawJson = useMemo(() => JSON.stringify(vc, null, 2), [vc])

  return (
    <Paper variant="outlined" sx={sx.card}>
      {/* ── Top section: achievement image + name + type ── */}
      <Box sx={sx.topCard}>
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
              {fields.issuanceDate && (
                <InfoBlock
                  header="Issuance Date"
                  value={formatDate(fields.issuanceDate)}
                />
              )}
              <Box sx={{ mt: fields.issuanceDate ? 2 : 0 }}>
                <InfoBlock
                  header="Expiration Date"
                  value={
                    fields.expirationDate
                      ? formatDate(fields.expirationDate)
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
                {fields.alignments.map((a: AlignmentItem, i: number) => (
                  <Box key={i}>
                    <Typography variant="body2" sx={sx.alignmentName}>
                      {a.targetName}
                    </Typography>
                    {a.targetUrl && (
                      <Link
                        href={a.targetUrl}
                        target="_blank"
                        rel="noopener"
                        variant="caption"
                      >
                        {a.targetUrl}
                      </Link>
                    )}
                    {a.targetDescription && (
                      <Typography variant="body2" color="text.secondary">
                        {a.targetDescription}
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
