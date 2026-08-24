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
  IconButton,
  Tooltip
} from '@mui/material'
import { MdCheck, MdContentCopy } from 'react-icons/md'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { getDisplayFields } from '@/lib/viewMappers/credentialDisplayFields'
import { formatDate } from '@/lib/viewMappers/formatDate'
import { getProofCreatedIso } from '@/lib/getProofCreatedIso'
import { useVerification } from '@/hooks/useVerification'
import { useCopyToClipboard } from '@/hooks/useCopyToClipboard'
import { IssuerInfo } from '@/components/credentialDetails/IssuerInfo'
import {
  VerificationPanel,
  VerificationStatusBadge
} from '@/components/credentialDetails/VerificationPanel'
import {
  InfoBlock,
  SectionHeader
} from '@/components/credentialDetails/InfoBlock'
import { CredentialActions } from '@/components/credentialDetails/CredentialActions'
import { ResumePreview } from '@/components/resume/ResumePreview'
import { ResumeCredentialCard } from '@/components/credentialDetails/ResumeCredentialCard'
import { JsonHighlight } from '@/components/JsonHighlight'
import { isResumeCredential } from '@/lib/isResumeCredential'
import { resumeSubjectToPreviewData } from '@/lib/viewMappers/resumeSubjectToPreviewData'
import {
  credentialDetailStyles,
  credentialDetailCardStyles as sx
} from '@/styles/credentialStyles'
import type {
  IAlignment,
  IVerifiableCredential
} from '@interop/data-integrity-core'
import type { CredentialDetailActions } from '@/types/credentialActions'
import { useTranslation } from 'react-i18next'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:credential')

export function CredentialDetail({
  vc,
  cid,
  actions
}: {
  vc: IVerifiableCredential
  cid?: string
  actions?: CredentialDetailActions
}) {
  const { t, i18n } = useTranslation()
  const hasActions = !!(actions?.onDelete || actions?.share)
  const fields = useMemo(() => getDisplayFields(vc), [vc])
  const createdDate = useMemo(() => getProofCreatedIso(vc), [vc])
  const verification = useVerification(vc)
  const [showRaw, setShowRaw] = useState(false)
  const rawJson = useMemo(() => JSON.stringify(vc, null, 2), [vc])
  const { copied, copy: copyRawJson } = useCopyToClipboard({
    onError: (err: unknown) => {
      log.error('Could not copy credential JSON', { err })
    }
  })
  const evidenceList = useMemo(() => {
    const raw = (vc as Record<string, unknown>).evidence
    if (!raw) {
      return []
    }
    const arr = Array.isArray(raw) ? raw : [raw]
    return arr as Array<{ id?: string; name?: string; description?: string }>
  }, [vc])
  const showResumePreview = useMemo(() => isResumeCredential(vc), [vc])
  const resumePreviewData = useMemo(
    () => (showResumePreview ? resumeSubjectToPreviewData(vc) : null),
    [vc, showResumePreview]
  )

  if (showResumePreview && resumePreviewData) {
    return (
      <Stack spacing={2} sx={sx.credentialStack}>
        <Box>
          {hasActions && actions && (
            <CredentialActions actions={actions} containerSx={sx.actionsRow} />
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
          onToggleRaw={() => setShowRaw(prev => !prev)}
        />

        <Divider />

        <ResumePreview data={resumePreviewData} />
      </Stack>
    )
  }

  return (
    <Stack spacing={2} sx={sx.credentialStack}>
      <Paper variant="outlined" sx={sx.card}>
        <Box sx={sx.topCard}>
          <Box sx={sx.badgeRow}>
            <VerificationStatusBadge
              loading={verification.loading}
              result={verification.result}
              error={verification.error}
            />
            {hasActions && actions && (
              <CredentialActions
                actions={actions}
                containerSx={sx.cardActions}
              />
            )}
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
                  {t('credential.achievementType')} {fields.achievementType}
                </Typography>
              )}
            </Box>
          </Box>
        </Box>

        <Box sx={sx.mainCard}>
          <Box sx={sx.secondaryColumn}>
            <Stack spacing={3}>
              <IssuerInfo
                issuer={vc.issuer}
                cid={cid}
                registryLoading={verification.loading}
                issuerRegistry={verification.issuerRegistry}
              />

              <InfoBlock
                header={t('credential.createdDate')}
                value={
                  createdDate
                    ? formatDate({
                        isoDate: createdDate,
                        locale: i18n.language
                      })
                    : t('common.na')
                }
              />
              <Box sx={{ mt: 0 }}>
                <InfoBlock
                  header={t('credential.expirationDate')}
                  value={
                    fields.expirationDate
                      ? formatDate({
                          isoDate: fields.expirationDate,
                          locale: i18n.language
                        })
                      : t('common.na')
                  }
                />
              </Box>
            </Stack>
          </Box>

          <Divider orientation="vertical" flexItem sx={sx.dividerVertical} />
          <Divider sx={sx.dividerHorizontal} />

          <Box sx={sx.primaryColumn}>
            {fields.issuedTo && (
              <InfoBlock
                header={t('credential.issuedTo')}
                value={fields.issuedTo}
              />
            )}

            {fields.credentialDescription && (
              <InfoBlock
                header={t('credential.description')}
                value={fields.credentialDescription}
              />
            )}

            {fields.criteria && (
              <Box>
                <SectionHeader>{t('credential.criteria')}</SectionHeader>
                <Box sx={sx.markdownBody}>
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {fields.criteria}
                  </ReactMarkdown>
                </Box>
              </Box>
            )}

            {fields.alignments.length > 0 && (
              <Box>
                <SectionHeader>{t('credential.alignments')}</SectionHeader>
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

            {evidenceList.length > 0 && (
              <Box>
                <SectionHeader>{t('credential.evidence')}</SectionHeader>
                <Stack spacing={1}>
                  {evidenceList.map((ev, i) => (
                    <Box key={i}>
                      {ev.id ? (
                        <Link
                          href={ev.id}
                          target="_blank"
                          rel="noopener"
                          variant="body2"
                        >
                          {ev.name || ev.id}
                        </Link>
                      ) : (
                        <Typography variant="body2">{ev.name}</Typography>
                      )}
                      {ev.description && (
                        <Typography variant="caption" color="text.secondary">
                          {ev.description}
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
            onClick={() => setShowRaw(prev => !prev)}
            sx={sx.rawToggle}
          >
            {showRaw ? t('credential.hideJson') : t('credential.viewSource')}
          </Button>
          <Collapse in={showRaw} unmountOnExit>
            <Box sx={sx.codeBlockWrapper}>
              <Tooltip title={copied ? t('common.copied') : t('common.copy')}>
                <IconButton
                  size="small"
                  aria-label={t('common.copy')}
                  onClick={() => {
                    void copyRawJson(rawJson)
                  }}
                  sx={sx.codeBlockCopyButton}
                >
                  {copied ? <MdCheck /> : <MdContentCopy />}
                </IconButton>
              </Tooltip>
              <JsonHighlight
                code={rawJson}
                sx={credentialDetailStyles.codeBlock}
              />
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
