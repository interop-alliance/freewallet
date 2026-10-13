/**
 * The "Storage access" section of the CHAPI login consent screen: one row per
 * requested capability, showing the relying party's reason, the recipient DID
 * the capability is delegated to, a human-readable target, the actions to be
 * granted, and the expiry. An encrypted collection the grantee joins no key
 * roster of gets a ciphertext note; write grants get a warning banner, the warning border, and the
 * shorter write expiry; public-collection grants get a warning banner stating
 * anyone on the web can read the collection (and, being plaintext, never a
 * ciphertext note); unsatisfiable grants render greyed with a "cannot
 * fulfill" note. Because the RP-supplied `reason` is attacker-controlled free
 * text, it renders through `SiteProvidedText` -- type-guarded, under an
 * explicit "the site says" attribution label, and truncated textually as well
 * as clamped, so it can neither read as wallet copy nor push the trusted rows
 * below the fold (for a screen reader too) -- and the recipient DID is
 * rendered separately with its own label and a monospace style so it cannot
 * be spoofed by the reason. The recipient row renders whenever there is a
 * recipient to show: a `controller` DID, or App Connect's wallet marking
 * (`walletMintedRecipient`) -- on a returning visit the copy states custody
 * ("stored in your wallet"), not provenance, since the app-key match
 * authenticates internal consistency only; on first run, before the DID
 * exists, the mint really is about to happen in this wallet and the copy says
 * so. Display-only -- approval is the single Continue button on the parent
 * page.
 *
 * The expiry line's day counts are the caller's ({@link grantTtlDays}): what
 * the mint will actually produce, which under a transient session's generation
 * delegation is the configured TTL clamped to that parent. The panel states
 * them; it does not derive them.
 *
 * A share grant (`https://w3id.org/byoe#shared-wallet-collection`) is the strongest thing this
 * panel can show and is rendered unmistakably differently: a heavier border
 * and a filled callout that says the grant is read AND decrypt, that it covers
 * everything already stored in the collection, and -- pre-stated, before
 * approval -- the honest ceiling that removing access later cannot take back
 * what has already been read. It never shows the ordinary "only sees
 * ciphertext" note, which would be exactly wrong.
 *
 * A private-collection grant naming a collection that already stands states
 * so on the row, from the resolver's `existing` reading: created by another
 * application (a warning naming that app where the wallet's records know
 * it, else the creator origin, else its DID; an agent by its stamped name,
 * else its shortened DID), unattributed, or left by an
 * earlier connection of the same application. The admitted app reads every
 * key epoch the collection has, and the row says so before approval. The
 * reading is absent until the caller has read the collection's attribution,
 * so the row shows no note the metadata has yet to refine.
 *
 * The inbox grant (`https://w3id.org/byoe#inbox`, a connection request's
 * one write) has its own row copy: it can send messages to the wallet. It
 * gets no write banner and no warning border, since it can create a message
 * and do nothing else. On a connection request every row states the share
 * TTL the grant takes, and that access renews while the connection stands.
 * Each read row also states that the agent passes read access on to people
 * it chooses.
 *
 * What is the same on every row is stated once, in a summary above the
 * list. The recipient block moves there when every grant names the same
 * recipient, which an App Connect request always does. The expiry sentence
 * moves there when a strict majority of the grants its revoke note covers
 * share it (so a request with one grant states it there too), and a grant
 * whose sentence differs states its own on its card. The revoke note is
 * always stated there. A share's own revoke note stays on its card
 * when ordinary grants sit beside it. The consolidation compares the values
 * themselves, not the request kind, so the interaction-URL page gets the
 * same treatment. The warnings stay on their cards.
 */
import Box from '@mui/material/Box'
import Chip from '@mui/material/Chip'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import {
  isSatisfiable,
  type ExistingCollectionReading,
  type ResolvedGrant
} from '@/lib/walletRequest'
import { SiteProvidedText } from './SiteProvidedText'

/**
 * A human-readable label for a resolved grant's target. A collection target
 * renders its id as a distinct monospace badge so it stands out from the
 * surrounding copy; the other targets stay plain text.
 */
function targetLabel(grant: ResolvedGrant, t: TFunction) {
  const { target } = grant
  if (target.targetClass === 'inbox') {
    return t('chapi.get.zcapTarget.inbox')
  }
  if (target.collectionId) {
    return (
      <>
        {t('chapi.get.zcapTarget.collection')}{' '}
        <Chip
          component="span"
          size="small"
          label={target.collectionId}
          sx={{ fontFamily: 'monospace' }}
        />
      </>
    )
  }
  if (target.invocationTarget) {
    try {
      return new URL(target.invocationTarget).pathname
    } catch {
      return target.invocationTarget
    }
  }
  return ''
}

/**
 * A row's expiry sentence. A share's covers the fetch axis only. A
 * connection request's grants all take the share TTL and renew while the
 * connection stands. Any other row states its read or write TTL.
 *
 * @param options {object}
 * @param options.t {Function}
 * @param options.share {boolean}
 * @param options.connectionRequest {boolean}
 * @param options.write {boolean}
 * @param options.ttlDays {number}
 * @param options.writeTtlDays {number}
 * @param options.shareTtlDays {number}
 * @returns {string}
 */
function expiryLine({
  t,
  share,
  connectionRequest,
  write,
  ttlDays,
  writeTtlDays,
  shareTtlDays
}: {
  t: TFunction
  share: boolean
  connectionRequest: boolean
  write: boolean
  ttlDays: number
  writeTtlDays: number
  shareTtlDays: number
}): string {
  if (share) {
    return t('chapi.get.zcapShareExpiry', { days: shareTtlDays })
  }
  if (connectionRequest) {
    return t('chapi.get.zcapConnectionExpiry', { days: shareTtlDays })
  }
  return t('chapi.get.zcapExpiry', { days: write ? writeTtlDays : ttlDays })
}

/**
 * The value held by every entry, or by a strict majority of them. A value
 * held by a single entry among several is no common value, and neither is
 * one half of an even split, so in both cases each entry keeps its own.
 *
 * @param values {string[]}
 * @returns {string | undefined}
 */
function commonValue(values: string[]): string | undefined {
  const counts = new Map<string, number>()
  for (const value of values) {
    counts.set(value, (counts.get(value) ?? 0) + 1)
  }
  let best: string | undefined
  let bestCount = 0
  for (const [value, count] of counts) {
    if (count > bestCount) {
      best = value
      bestCount = count
    }
  }
  return bestCount * 2 > values.length ? best : undefined
}

/**
 * Whether there is a recipient to show: a `controller` DID, or App Connect's
 * wallet marking.
 *
 * @param options {object}
 * @param [options.controller] {string}
 * @param options.walletMintedRecipient {boolean}
 * @returns {boolean}
 */
function hasRecipient({
  controller,
  walletMintedRecipient
}: {
  controller?: string
  walletMintedRecipient: boolean
}): boolean {
  return Boolean(controller) || walletMintedRecipient
}

/**
 * The recipient block: the "Access granted to:" label, the recipient DID in
 * monospace on its own line, and App Connect's wallet marking. Renders
 * nothing when there is no recipient to show.
 *
 * @param options {object}
 * @param options.t {Function}
 * @param [options.controller] {string}
 * @param options.walletMintedRecipient {boolean}
 */
function RecipientBlock({
  t,
  controller,
  walletMintedRecipient
}: {
  t: TFunction
  controller?: string
  walletMintedRecipient: boolean
}) {
  if (!hasRecipient({ controller, walletMintedRecipient })) {
    return null
  }
  return (
    <Box sx={{ mb: 0.5 }}>
      <Typography
        variant="caption"
        color="text.secondary"
        sx={{ display: 'block' }}
      >
        {t('chapi.get.zcapRecipient')}
      </Typography>
      {controller && (
        <Typography
          variant="caption"
          component="div"
          sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}
        >
          {controller}
        </Typography>
      )}
      {walletMintedRecipient && (
        <Typography
          variant="caption"
          color="text.secondary"
          sx={{ display: 'block' }}
        >
          {t(
            controller
              ? 'chapi.get.zcapRecipientWalletStored'
              : 'chapi.get.zcapRecipientWalletMintedPending'
          )}
        </Typography>
      )}
    </Box>
  )
}

// The existing-collection note per creator reading; `this-app` (the
// requester's own collection) gets none.
const EXISTING_NOTES: Partial<
  Record<ExistingCollectionReading['creator'], { key: string; color: string }>
> = {
  other: { key: 'chapi.get.zcapExistingOther', color: 'warning.main' },
  unattributed: {
    key: 'chapi.get.zcapExistingUnattributed',
    color: 'text.secondary'
  },
  'this-application': {
    key: 'chapi.get.zcapExistingApplication',
    color: 'text.secondary'
  }
}

export function ZcapGrantsPanel({
  grants,
  ttlDays,
  writeTtlDays,
  shareTtlDays,
  walletMintedRecipient = false,
  connectionRequest = false,
  heading
}: {
  grants: ResolvedGrant[]
  ttlDays: number
  writeTtlDays: number
  shareTtlDays: number
  // A connection request: every grant takes the share TTL and renews while
  // the connection stands, and the agent passes read access on.
  connectionRequest?: boolean
  // App Connect consent: the recipient identity lives in this user's wallet
  // (matched from the credential store, or about to be minted on first run),
  // and the row says so. The matched copy claims custody, not provenance --
  // the match cannot prove who created the credential.
  walletMintedRecipient?: boolean
  // Overrides the default "Storage access" section heading (App Connect uses
  // app-centric phrasing).
  heading?: string
}) {
  const { t } = useTranslation()

  // A satisfiable grant's expiry sentence. An unsatisfiable grant states
  // none.
  const expiryOf = (grant: ResolvedGrant) =>
    expiryLine({
      t,
      share: grant.target.targetClass === 'share',
      connectionRequest,
      write: grant.write,
      ttlDays,
      writeTtlDays,
      shareTtlDays
    })
  const satisfiableGrants = grants.filter(grant => isSatisfiable(grant.target))
  // The ordinary revoke note covers every grant but a share. With only
  // shares on the list, the share variant takes its place. The summary's
  // expiry is drawn from the grants its revoke note covers, so a share's
  // expiry sentence stays beside the share revoke note on its card when
  // ordinary grants are present.
  const ordinaryGrants = satisfiableGrants.filter(
    grant => grant.target.targetClass !== 'share'
  )
  const onlyShares = ordinaryGrants.length === 0
  const summaryGrants = onlyShares ? satisfiableGrants : ordinaryGrants
  const summaryRevokeNote =
    summaryGrants.length > 0 &&
    t(onlyShares ? 'chapi.get.zcapShareRevokeNote' : 'chapi.get.zcapRevokeNote')
  const sharedExpiry = commonValue(summaryGrants.map(expiryOf))
  const sharedRecipient =
    grants.length > 0 &&
    grants.every(
      grant => grant.descriptor.controller === grants[0].descriptor.controller
    )
  const summaryRecipient =
    sharedRecipient &&
    hasRecipient({
      controller: grants[0].descriptor.controller,
      walletMintedRecipient
    })
  const summaryLine = [sharedExpiry, summaryRevokeNote]
    .filter(Boolean)
    .join(' ')

  return (
    <Stack spacing={1}>
      <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
        {heading ?? t('chapi.get.zcapHeading')}
      </Typography>
      {(summaryRecipient || summaryLine) && (
        <Box data-testid="zcap-summary">
          {summaryRecipient && (
            <RecipientBlock
              t={t}
              controller={grants[0].descriptor.controller}
              walletMintedRecipient={walletMintedRecipient}
            />
          )}
          {summaryLine && (
            <Typography
              variant="caption"
              color="text.secondary"
              sx={{ display: 'block' }}
            >
              {summaryLine}
            </Typography>
          )}
        </Box>
      )}
      {grants.map((grant, index) => {
        const { target, allowedActions, descriptor, write } = grant
        const satisfiable = isSatisfiable(target)
        const share = target.targetClass === 'share'
        // A card states its own expiry only where it differs from the
        // summary's, and a share its own revoke note only beside ordinary
        // grants.
        const ownExpiry = satisfiable ? expiryOf(grant) : undefined
        const cardExpiryLine = [
          ownExpiry !== sharedExpiry && ownExpiry,
          share && !onlyShares && t('chapi.get.zcapShareRevokeNote')
        ]
          .filter(Boolean)
          .join(' ')
        // The inbox grant can only create messages, so it reads as neither
        // an ordinary write nor a read the agent passes on.
        const inbox = target.targetClass === 'inbox'
        const writeWarning = write && !inbox
        const existingNote =
          target.existing && EXISTING_NOTES[target.existing.creator]
        // Warning border for public-collection and write grants.
        const highlight =
          target.targetClass === 'public-collection' || writeWarning
        return (
          <Box
            key={descriptor.referenceId ?? index}
            data-testid="zcap-grant"
            sx={{
              px: 1.5,
              py: 1,
              // A share is the strongest grant here: a heavier border sets it
              // apart from the ordinary warning rows above and below it.
              border: share ? 2 : 1,
              borderColor: share || highlight ? 'warning.main' : 'divider',
              borderRadius: 2,
              opacity: satisfiable ? 1 : 0.6
            }}
          >
            <SiteProvidedText
              text={descriptor.reason}
              label={t('chapi.get.zcapReasonLabel')}
            />

            {!sharedRecipient && (
              <RecipientBlock
                t={t}
                controller={descriptor.controller}
                walletMintedRecipient={walletMintedRecipient}
              />
            )}

            {satisfiable ? (
              <>
                {/* The target and its action chips share one wrapping line. */}
                <Stack
                  direction="row"
                  sx={{
                    flexWrap: 'wrap',
                    alignItems: 'center',
                    columnGap: 1,
                    rowGap: 0.5
                  }}
                >
                  <Typography variant="subtitle2" component="span">
                    {targetLabel(grant, t)}
                  </Typography>
                  <Stack direction="row" sx={{ flexWrap: 'wrap', gap: 0.5 }}>
                    {allowedActions.map(action => (
                      <Chip key={action} size="small" label={action} />
                    ))}
                  </Stack>
                </Stack>

                {target.targetClass === 'public-collection' && (
                  <Typography
                    variant="caption"
                    color="warning.main"
                    sx={{ display: 'block', mt: 0.5 }}
                  >
                    {t('chapi.get.zcapPublicWarning')}
                  </Typography>
                )}

                {writeWarning && (
                  <Typography
                    variant="caption"
                    color="warning.main"
                    sx={{ display: 'block', mt: 0.5 }}
                  >
                    {t('chapi.get.zcapWriteWarning')}
                  </Typography>
                )}

                {inbox && (
                  <Typography
                    variant="caption"
                    color="text.secondary"
                    sx={{ display: 'block', mt: 0.5 }}
                  >
                    {t('chapi.get.zcapInboxNote')}
                  </Typography>
                )}

                {connectionRequest && !inbox && !share && (
                  <Typography
                    variant="caption"
                    color="text.secondary"
                    sx={{ display: 'block', mt: 0.5 }}
                  >
                    {t('chapi.get.zcapConnectionPassOn')}
                  </Typography>
                )}

                {target.existing && existingNote && (
                  <Typography
                    variant="caption"
                    color={existingNote.color}
                    sx={{ display: 'block', mt: 0.5 }}
                  >
                    {t(existingNote.key, {
                      creator:
                        target.existing.creatorName ??
                        target.existing.generator?.id
                    })}
                  </Typography>
                )}

                {share && (
                  <Box
                    sx={{
                      mt: 1,
                      p: 1,
                      borderRadius: 1,
                      bgcolor: 'warning.main',
                      color: 'warning.contrastText'
                    }}
                  >
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>
                      {t('chapi.get.zcapShareWarning')}
                    </Typography>
                    <Typography variant="caption" sx={{ display: 'block' }}>
                      {t('chapi.get.zcapShareExisting')}
                    </Typography>
                    <Typography
                      variant="caption"
                      sx={{ display: 'block', mt: 0.5 }}
                    >
                      {t('chapi.get.zcapShareCeiling')}
                    </Typography>
                  </Box>
                )}

                {/* A share decrypts, so the ciphertext-only note would be
                    exactly wrong; the callout above states the truth. */}
                {target.encrypted && !share && (
                  <Typography
                    variant="caption"
                    color="text.secondary"
                    sx={{ display: 'block', mt: 0.5 }}
                  >
                    {t('chapi.get.zcapEncryptedNote')}
                  </Typography>
                )}

                {cardExpiryLine && (
                  <Typography
                    variant="caption"
                    color="text.secondary"
                    sx={{ display: 'block', mt: 0.5 }}
                  >
                    {cardExpiryLine}
                  </Typography>
                )}
              </>
            ) : (
              <Typography variant="body2" color="text.secondary">
                {t('chapi.get.zcapCannotFulfill')}
              </Typography>
            )}
          </Box>
        )
      })}
    </Stack>
  )
}
