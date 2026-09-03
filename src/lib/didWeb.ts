/**
 * The did:web projection id of a promoted account. The wallet publishes no
 * did:web document of its own: `id/did.json` is written by the did:webvh
 * log's own projection, which is the whole account document with its ids
 * rewritten, so did:web resolution and did:webvh resolution of the same
 * account can never disagree.
 *
 * The projection is an ordinary WAS Resource served by the unauthenticated
 * public-read path, so hosting needs zero server changes: the DID's path
 * segments name the `id` collection that holds it --
 * `did:web:<host>:space:<spaceId>:id` resolves to
 * `https://<host>/space/<spaceId>/id/did.json`. The `id` collection carries a
 * collection-level `PublicCanRead` policy (set at provisioning), so every
 * resource in it is world-readable without a per-resource grant.
 *
 * The KMS `authentication` key that document publishes is provisioned by
 * `ensureKmsAuthentication` in `@/lib/kms`.
 */

/**
 * Builds the did:web projection id for a Space from the WAS server URL and
 * space id. The host segment is percent-encoded per the did:web method spec,
 * so a dev host with a port becomes `localhost%3A8080`. It matches
 * wallet-core's `didWebvhControllerTemplate` byte for byte, minus the method
 * and SCID, which is what makes the projection resolvable under this id.
 *
 * @param options {object}
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}
 * @returns {string}   e.g. `did:web:localhost%3A8080:space:<spaceId>:id`
 */
export function didWebFromSpace({
  wasServerUrl,
  spaceId
}: {
  wasServerUrl: string
  spaceId: string
}): string {
  const { host } = new URL(wasServerUrl)
  return `did:web:${encodeURIComponent(host)}:space:${spaceId}:id`
}
