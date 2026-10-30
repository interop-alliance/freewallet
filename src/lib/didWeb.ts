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
 * `did:web:<host>:<prefix...>:space:<spaceId>:id` resolves to
 * `https://<host>/<prefix>/space/<spaceId>/id/did.json`. The `id` collection
 * carries a collection-level `PublicCanRead` policy (set at provisioning),
 * so every resource in it is world-readable without a per-resource grant.
 *
 * The KMS `authentication` key that document publishes is provisioned by
 * `ensureKmsAuthentication` in `@/lib/kms`.
 */
import { convertWebvhIdToWebId } from '@interop/did-method-webvh'
import { didWebvhControllerTemplate } from '@interop/wallet-core/webvh'

/**
 * The did:web projection id of an account's did:webvh: the identifier with
 * the method and SCID dropped, through the library's own conversion so it
 * is the id `generateParallelDidWeb` writes into the projection (a lowercase
 * `%3a` port separator is brought to the canonical form the same way).
 *
 * @param options {object}
 * @param options.did {string}   the account's did:webvh
 * @returns {string}   e.g. `did:web:localhost%3A8080:space:<spaceId>:id`
 * @throws {Error}   the library's, when `did` is not a did:webvh id
 */
export function didWebOfAccount({ did }: { did: string }): string {
  return convertWebvhIdToWebId(did)
}

/**
 * The did:web projection id of an account Space's log before its SCID
 * exists: the KMS stage of a signup mints the `authentication` key ahead of
 * the genesis entry, so it names the key under this id. It is wallet-core's
 * controller template through the same conversion, which accepts the
 * `{SCID}` placeholder, so it is the id {@link didWebOfAccount} reads off
 * the published did:webvh, prefix segments included.
 *
 * @param options {object}
 * @param options.baseServerUrl {string}
 * @param options.spaceId {string}
 * @returns {string}   e.g. `did:web:localhost%3A8080:space:<spaceId>:id`
 */
export function didWebOfSpace({
  baseServerUrl,
  spaceId
}: {
  baseServerUrl: string
  spaceId: string
}): string {
  return convertWebvhIdToWebId(
    didWebvhControllerTemplate({ baseServerUrl, spaceId })
  )
}
