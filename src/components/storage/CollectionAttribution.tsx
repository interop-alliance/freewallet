/**
 * The "Created by ..." caption a collection carries in the storage browser:
 * the application it was provisioned for, by the name the wallet's records
 * hold for it (linked while the app is still connected), the bare origin
 * recorded at provisioning when no record names the app, or the wallet itself
 * for the collections it provisions.
 */
import Box from '@mui/material/Box'
import Link from '@mui/material/Link'
import Typography from '@mui/material/Typography'
import { Trans, useTranslation } from 'react-i18next'
import { Link as RouterLink } from 'react-router'
import type { CollectionCreator } from '@/lib/connectedApps'
import type { StorageCollection } from '@/lib/storage'
import { storageStyles } from '@/styles/appStyles'
import { isWalletCollection } from './displayUtils'

export function CollectionAttribution({
  collection,
  creator,
  linkToApp = true
}: {
  collection: StorageCollection
  creator?: CollectionCreator
  /**
   * False where the caption sits inside a row that is itself a link (the
   * folder card): the app name is then plain text, since interactive content
   * cannot nest in a link. The collection's own page carries the link.
   */
  linkToApp?: boolean
}) {
  const { t } = useTranslation()

  const caption = isWalletCollection(collection.id)
    ? t('storage.createdByWallet')
    : appCaption({ collection, creator, linkToApp })
  if (!caption) {
    return null
  }
  return (
    <Typography
      variant="caption"
      component="div"
      sx={storageStyles.collectionAttribution}
    >
      {caption}
    </Typography>
  )
}

/**
 * The app half of the caption: a creator the wallet's records name is named,
 * and linked to its Applications row while it is still connected; one
 * stamped with an origin alone names that origin as plain text; one with
 * neither has no caption.
 */
function appCaption({
  collection,
  creator,
  linkToApp
}: {
  collection: StorageCollection
  creator?: CollectionCreator
  linkToApp: boolean
}) {
  const label = creator?.name ?? collection.generatorOrigin
  if (!label) {
    return null
  }
  const nameComponent =
    creator?.cid && linkToApp ? (
      <Link
        component={RouterLink}
        to={`/applications/${creator.cid}`}
        underline="hover"
      />
    ) : (
      <Box component="span" />
    )
  return (
    <Trans
      i18nKey="storage.createdByApp"
      values={{ name: label }}
      components={{ app: nameComponent }}
    />
  )
}
