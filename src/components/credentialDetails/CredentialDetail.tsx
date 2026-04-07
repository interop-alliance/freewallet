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
import { getDisplayFields } from '@/lib/viewMappers/credentialDisplayFields'
import { formatDate } from '@/lib/viewMappers/formatDate'
import { getProofCreatedIso } from '@/lib/getProofCreatedIso'
import { useVerification } from '@/hooks/useVerification'
import { IssuerInfo } from '@/components/credentialDetails/IssuerInfo'
import {
  VerificationPanel,
  VerificationStatusBadge
} from '@/components/credentialDetails/VerificationPanel'
import {
  InfoBlock,
  SectionHeader
} from '@/components/credentialDetails/InfoBlock'
import { ResumePreview } from '@/components/resume/ResumePreview'
import { ResumeCredentialCard } from '@/components/credentialDetails/ResumeCredentialCard'
import { isResumeCredential } from '@/lib/isResumeCredential'
import { resumeSubjectToPreviewData } from '@/lib/viewMappers/resumeSubjectToPreviewData'
import {
  credentialDetailStyles,
  credentialDetailCardStyles as sx
} from '@/styles/credentialStyles'
import type { IAlignment, IVerifiableCredential } from '@digitalcredentials/ssi'

export function CredentialDetail({
  vc,
  onDelete
}: {
  vc: IVerifiableCredential
  onDelete?: () => void
}) {
  const fields = useMemo(() => getDisplayFields(vc), [vc])
  const createdDate = useMemo(() => getProofCreatedIso(vc), [vc])
  const verification = useVerification(vc)
  const [showRaw, setShowRaw] = useState(false)
  const rawJson = useMemo(() => JSON.stringify(vc, null, 2), [vc])
  const showResumePreview = useMemo(() => isResumeCredential(vc), [vc])
  const resumePreviewData = useMemo(
    () => (showResumePreview ? resumeSubjectToPreviewData(vc) : null),
    [vc, showResumePreview]
  )

  if (showResumePreview && resumePreviewData) {
    return (
      <Stack spacing={2} sx={sx.credentialStack}>
        <Box
          sx={{
            position: 'relative',
            ...(onDelete ? { pr: { xs: 5, md: 6 } } : {})
          }}
        >
          {onDelete && (
            <IconButton
              size="small"
              onClick={onDelete}
              aria-label="Delete credential"
              sx={{ position: 'absolute', top: 0, right: 0 }}
            >
              <MdDeleteOutline size={24} />
            </IconButton>
          )}
          <Typography variant="h5" component="h2" sx={sx.credentialName}>
            {fields.credentialName}
          </Typography>
        </Box>

        <ResumeCredentialCard
          vc={vc}
          createdDate={createdDate}
          verification={verification}
          showRaw={showRaw}
          rawJson={rawJson}
          onToggleRaw={() => {
            setShowRaw(prev => !prev)
            if (!showRaw) {
              requestAnimationFrame(() => microlightReset())
            }
          }}
        />

        <Divider />

        <ResumePreview data={resumePreviewData} />
      </Stack>
    )
  }

  return (
    <Stack spacing={2} sx={sx.credentialStack}>
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

        <Box
          sx={{
            ...sx.topCard,
            ...(onDelete ? { pr: { xs: 5, md: 6 } } : {})
          }}
        >
          <Box sx={sx.badgeRow}>
            <VerificationStatusBadge
              loading={verification.loading}
              result={verification.result}
              error={verification.error}
            />
          </Box>
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

        <Box sx={sx.mainCard}>
          <Box sx={sx.secondaryColumn}>
            <Stack spacing={3}>
              <IssuerInfo issuer={vc.issuer} />

              <InfoBlock
                header="Created date"
                value={
                  createdDate ? formatDate({ isoDate: createdDate }) : 'N/A'
                }
              />
              <Box sx={{ mt: 0 }}>
                <InfoBlock
                  header="Expiration Date"
                  value={
                    fields.expirationDate
                      ? formatDate({ isoDate: fields.expirationDate })
                      : 'N/A'
                  }
                />
              </Box>
            </Stack>
          </Box>

          <Divider orientation="vertical" flexItem sx={sx.dividerVertical} />
          <Divider sx={sx.dividerHorizontal} />

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
      <Paper variant="outlined" sx={sx.card}>
        <VerificationPanel verification={verification} />
      </Paper>
    </Stack>
  )
}
