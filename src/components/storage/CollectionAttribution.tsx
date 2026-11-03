/**
 * The "Created for ..." caption a collection carries in the storage browser:
 * the requester it was provisioned for, by the name stamped on the
 * collection's `generator` or else the name its `connections` entry holds
 * for it (linked while the app is still connected), the bare origin recorded at
 * provisioning when neither names the app, or "Created by this wallet" for
 * the collections the wallet provisions for itself. The naming order is
 * `collectionCreatorLabel`'s, an interaction-URL agent's stamp included. The
 * stamp is the wallet's own record of whom it created the collection for,
 * so the verb is "for" on every surface, apart from the server-observed
 * "Created by" line that stands beside it on the collection contents page.
 * Where that line also names the wallet, the wallet-collection caption is
 * left out, since the two would state one fact twice.
 */
import type { ReactNode } from 'react'
import Box from '@mui/material/Box'
import Link from '@mui/material/Link'
import Typography from '@mui/material/Typography'
import { Trans, useTranslation } from 'react-i18next'
import { Link as RouterLink } from 'react-router'
import { collectionCreatorLabel } from '@/lib/collectionAttribution'
import type { CollectionCreator } from '@/lib/connectedApps'
import type { StorageCollection } from '@/lib/storage'
import { storageStyles } from '@/styles/appStyles'
import { isWalletCollection } from './displayUtils'

export function CollectionAttribution({
  collection,
  creator,
  observedByWallet = false,
  linkToApp = true
}: {
  collection: StorageCollection
  creator?: CollectionCreator
  /**
   * True where the server-observed creator line beside this caption already
   * reads as this wallet. A wallet collection then renders no caption.
   */
  observedByWallet?: boolean
  /**
   * False where the caption sits inside a row that is itself a link (the
   * folder card): the app name is then plain text, since interactive content
   * cannot nest in a link. The collection's own page carries the link.
   */
  linkToApp?: boolean
}) {
  const { t } = useTranslation()

  if (isWalletCollection(collection.id)) {
    return observedByWallet ? null : (
      <AttributionCaption>{t('storage.createdByWallet')}</AttributionCaption>
    )
  }
  const caption = creatorCaption({ collection, creator, linkToApp })
  if (!caption) {
    return null
  }
  return <AttributionCaption>{caption}</AttributionCaption>
}

/**
 * The caption shell every creator line in the storage browser shares.
 */
export function AttributionCaption({ children }: { children: ReactNode }) {
  return (
    <Typography
      variant="caption"
      component="div"
      sx={storageStyles.collectionAttribution}
    >
      {children}
    </Typography>
  )
}

/**
 * A creator line naming one party: the `<app>` slot of the i18n key holds
 * the name, linked to the party's application detail page when its entry
 * resource id is given (while the Applications page lists it), and plain
 * text otherwise.
 */
export function NamedCreatorCaption({
  i18nKey,
  name,
  resourceId
}: {
  i18nKey: string
  name: string
  resourceId?: string
}) {
  const nameComponent = resourceId ? (
    <Link
      component={RouterLink}
      to={`/applications/${resourceId}`}
      underline="hover"
    />
  ) : (
    <Box component="span" />
  )
  return (
    <Trans
      i18nKey={i18nKey}
      values={{ name }}
      components={{ app: nameComponent }}
    />
  )
}

/**
 * The stamped-creator half of the caption: the creator's label, linked to
 * its application detail page while the Applications page lists the app,
 * and plain text otherwise; a collection with no stamp has no
 * caption.
 */
function creatorCaption({
  collection,
  creator,
  linkToApp
}: {
  collection: StorageCollection
  creator?: CollectionCreator
  linkToApp: boolean
}) {
  const label = collectionCreatorLabel({
    generator: collection.generator,
    recordName: creator?.name
  })
  if (!label) {
    return null
  }
  return (
    <NamedCreatorCaption
      i18nKey="storage.createdForApp"
      name={label}
      {...(linkToApp &&
        creator?.resourceId && { resourceId: creator.resourceId })}
    />
  )
}
