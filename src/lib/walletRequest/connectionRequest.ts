/**
 * The connection request's vocabulary, shared by the grant resolver, the
 * interaction-URL precheck, and the consent sequence: the `#inbox` target
 * descriptor, and the test that tells a connection request from any other
 * interaction-URL request. A connection request is an interaction-URL
 * request whose grants include an `#inbox` target. Dependency free, so each
 * reader agrees on the test without importing another's module.
 */
import type { ICapabilityQueryDetail } from './types'

/**
 * The descriptor type that names this Space's `inbox` collection as a grant
 * target. The descriptor carries no `name`, since the collection is fixed.
 * The bundled byoe context does not define the term yet, so the IRI is
 * written out here.
 */
export const INBOX_DESCRIPTOR_TYPE = 'https://w3id.org/byoe#inbox'

/**
 * Whether an `invocationTarget` is the `#inbox` descriptor: an object whose
 * `type` is {@link INBOX_DESCRIPTOR_TYPE} and that carries no `name`. A
 * plain URL string naming the inbox container is not this descriptor.
 *
 * @param target {unknown}   a capability query's `invocationTarget`
 * @returns {boolean}
 */
export function isInboxDescriptor(target: unknown): boolean {
  if (!target || typeof target !== 'object' || Array.isArray(target)) {
    return false
  }
  const { type, name } = target as { type?: unknown; name?: unknown }
  return type === INBOX_DESCRIPTOR_TYPE && name === undefined
}

/**
 * Whether a set of capability queries forms a connection request: at least
 * one names the `inbox` by its descriptor. Only an interaction-URL request
 * can be one; the caller decides the request path.
 *
 * @param options {object}
 * @param options.zcapRequests {ICapabilityQueryDetail[]}
 * @returns {boolean}
 */
export function namesInboxTarget({
  zcapRequests
}: {
  zcapRequests: ICapabilityQueryDetail[]
}): boolean {
  return zcapRequests.some(({ invocationTarget }) =>
    isInboxDescriptor(invocationTarget)
  )
}
