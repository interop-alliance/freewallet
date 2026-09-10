/**
 * Attributing a stored collection to the connected application it was
 * provisioned for, for the storage browser's "Created by" line.
 *
 * The signal is the Collection Description's `generator`, the app's did:key
 * stamped when App Connect provisioning created the collection. It is matched
 * against the subject DIDs of the apps the wallet holds keys for; the newest
 * connect wins a subject DID, since `listConnectedApps` returns its apps
 * latest-connected first. A collection carrying no `generator` is
 * unattributed.
 */
import type { ConnectedApp } from '@/lib/connectedApps'
import type { StorageCollection } from '@/lib/storage'

/**
 * Maps each collection that belongs to a connected application onto that app.
 * Collections with no attribution, and collections naming an app the wallet
 * no longer holds a key for (revoked, or connected on another client), are
 * absent from the map.
 *
 * @param options {object}
 * @param options.collections {StorageCollection[]}   the Space's listing
 * @param options.apps {ConnectedApp[]}   `listConnectedApps` output, in its
 *   latest-connected-first order
 * @returns {Map<string, ConnectedApp>}   keyed by collection id
 */
export function attributeCollectionsToApps({
  collections,
  apps
}: {
  collections: StorageCollection[]
  apps: ConnectedApp[]
}): Map<string, ConnectedApp> {
  // Latest connect first, so the first entry for a subject DID stays.
  const bySubjectDid = new Map<string, ConnectedApp>()
  for (const app of apps) {
    if (app.subjectDid && !bySubjectDid.has(app.subjectDid)) {
      bySubjectDid.set(app.subjectDid, app)
    }
  }

  const attribution = new Map<string, ConnectedApp>()
  for (const collection of collections) {
    const app = collection.generator
      ? bySubjectDid.get(collection.generator)
      : undefined
    if (app) {
      attribution.set(collection.id, app)
    }
  }
  return attribution
}
