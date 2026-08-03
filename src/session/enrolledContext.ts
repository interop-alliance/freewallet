/**
 * The enrolled-client context: the preconditions shared by every ceremony that
 * acts AS the account -- recovery-code issuance and revocation, client
 * revocation, and the Settings clients surface. All of them need the same four
 * things (a configured storage server with a remote store, a promoted
 * did:webvh account pointer, this client's did:webvh update keys, and this
 * client's identity key-agreement key), so they are resolved once here.
 *
 * The boolean gates the UI enables its buttons on are DERIVED from the same
 * resolution rather than restating it, so a gate and its ceremony cannot
 * disagree -- the failure mode that left Disconnect enabled on a session
 * holding no client key material, which then threw mid-ceremony.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import {
  isWebvhDid,
  type ClientWebvhUpdateKeys
} from '@interop/wallet-core/webvh'
import { WAS_SERVER_URL } from '@/app.config'
import type { Session } from '@/types/auth'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'

/**
 * What an enrolled client holds, resolved from a live session: the remote
 * store the ceremony writes through, the promoted account pointer (its `did`
 * narrowed to a string by the did:webvh check), this client's own key
 * material, and the account controller the records it mints restate.
 */
export interface EnrolledClientContext {
  remoteStore: WASRemoteStore
  pointer: AccountPointer & { did: string }
  clientWebvhKeys: ClientWebvhUpdateKeys
  clientKeyAgreementKey: IKeyAgreementKey
  controller: string
}

/**
 * Which precondition a session misses, in the order they are checked.
 */
type MissingPrecondition =
  'storage' | 'pointer' | 'updateKeys' | 'keyAgreementKey'

/**
 * Resolves the enrolled-client context, or names the first precondition the
 * session misses.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {{ context: EnrolledClientContext } | { missing: MissingPrecondition }}
 */
function resolveEnrolledClientContext({
  session
}: {
  session: Session
}): { context: EnrolledClientContext } | { missing: MissingPrecondition } {
  const remoteStore = session.storage.remoteStore
  if (!WAS_SERVER_URL || !remoteStore || session.isGuest) {
    return { missing: 'storage' }
  }
  const { profile } = session
  const pointer = profile.accountPointer
  if (!pointer || !isWebvhDid(pointer.did)) {
    return { missing: 'pointer' }
  }
  if (!profile.clientWebvhKeys) {
    return { missing: 'updateKeys' }
  }
  if (!profile.clientKeyAgreementKey) {
    return { missing: 'keyAgreementKey' }
  }
  return {
    context: {
      remoteStore,
      // The did:webvh guard above is what makes `did` a string here, so the
      // pointer handed back names the account the log must resolve to.
      pointer: { ...pointer, did: pointer.did },
      clientWebvhKeys: profile.clientWebvhKeys,
      clientKeyAgreementKey: profile.clientKeyAgreementKey,
      controller: profile.accountController ?? session.user.id
    }
  }
}

/**
 * The enrolled-client context, or `null` when this session cannot act as the
 * account. The non-throwing form, for the UI gates and for callers that
 * degrade rather than fail.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {EnrolledClientContext | null}
 */
export function enrolledClientContext({
  session
}: {
  session: Session
}): EnrolledClientContext | null {
  const resolved = resolveEnrolledClientContext({ session })
  return 'context' in resolved ? resolved.context : null
}

/**
 * The enrolled-client context, or a throw naming the missing precondition.
 * Callers gate on the derived boolean first, so a throw here is defensive.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.action {string}   the ceremony's name, as the error message
 *   opens ("Client revocation requires ...")
 * @returns {EnrolledClientContext}
 */
export function requireEnrolledClientContext({
  session,
  action
}: {
  session: Session
  action: string
}): EnrolledClientContext {
  const resolved = resolveEnrolledClientContext({ session })
  if ('context' in resolved) {
    return resolved.context
  }
  switch (resolved.missing) {
    case 'storage':
      throw new Error(`${action} requires a configured storage server.`)
    case 'pointer':
      throw new Error(
        `${action} requires a promoted did:webvh account; this account has ` +
          'not finished provisioning.'
      )
    case 'updateKeys':
      throw new Error(`${action} requires this client's did:webvh update keys.`)
    default:
      throw new Error(`${action} requires this client's key-agreement key.`)
  }
}
