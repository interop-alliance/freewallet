/**
 * The "Created by ..." caption a collection carries in the storage browser:
 * the connected application it was provisioned for, the bare origin recorded
 * at provisioning when the wallet no longer holds that app's key, or the
 * wallet itself for the collections it provisions.
 */
import Box from '@mui/material/Box'
import Link from '@mui/material/Link'
import Typography from '@mui/material/Typography'
import { Trans, useTranslation } from 'react-i18next'
import { Link as RouterLink } from 'react-router'
import type { ConnectedApp } from '@/lib/connectedApps'
import type { StorageCollection } from '@/lib/storage'
import { storageStyles } from '@/styles/appStyles'
import { isWalletCollection } from './displayUtils'

export function CollectionAttribution({
  collection,
  app,
  linkToApp = true
}: {
  collection: StorageCollection
  app?: ConnectedApp
  /**
   * False where the caption sits inside a row that is itself a link (the
   * folder card): the app name is then plain text, since interactive content
   * cannot nest in a link. The collection's own page carries the link.
   */
  linkToApp?: boolean
}) {
  const { t } = useTranslation()

  if (isWalletCollection(collection.id)) {
    return (
      <Typography
        variant="caption"
        component="div"
        sx={storageStyles.collectionAttribution}
      >
        {t('storage.createdByWallet')}
      </Typography>
    )
  }

  // A collection whose app the wallet still holds a key for links to it; one
  // stamped with an origin alone names that origin as plain text.
  const label = app?.name ?? collection.generatorOrigin
  if (!label) {
    return null
  }
  const nameComponent =
    app && linkToApp ? (
      <Link
        component={RouterLink}
        to={`/applications/${app.cid}`}
        underline="hover"
      />
    ) : (
      <Box component="span" />
    )

  return (
    <Typography
      variant="caption"
      component="div"
      sx={storageStyles.collectionAttribution}
    >
      <Trans
        i18nKey="storage.createdByApp"
        values={{ name: label }}
        components={{ app: nameComponent }}
      />
    </Typography>
  )
}
