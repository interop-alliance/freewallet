/**
 * Composes a Verifiable Presentation to send back to a requester. The signing
 * itself lives in the shared `@interop/wallet-core/request` `composeVp`; this
 * wrapper resolves Freewallet's signer + holder from the `Session` and the
 * request's own queries (the three-way holder dispatch below), and enforces
 * Freewallet's stricter DID Auth rule (a `domain` is required, where the
 * shared guard requires only a `challenge`).
 *
 * The shared `composeVp` appends the hosted App Connect context URL
 * (`https://w3id.org/byoe/app-connect/v1`) when grants or the App Connect
 * marker are embedded; the loader below resolves it from the bundled
 * `byoe-context` document, so no fetch happens at signing time.
 */
import {
  composeVp,
  DEFAULT_PRESENTABLE_DID_METHODS,
  didAuthMethodSupported
} from '@interop/wallet-core/request'
import type {
  IVPRQuery,
  PresentationSigner
} from '@interop/wallet-core/request'
import {
  clientSigningKeyMultibase,
  isWebvhDid,
  multibaseOf,
  relationIds
} from '@interop/wallet-core/webvh'
import { securityLoader } from '@interop/security-document-loader'
import { contexts as byoeContexts } from 'byoe-context'
import type { Session } from '@/types/auth'
import { didWebFromSpace } from '@/lib/didWeb'
import { kmsAuthenticationSigner } from '@/lib/kms'
import { peekVerifiedAccountLog } from '@/session/verifiedLog'
import type {
  IVerifiableCredential,
  IVerifiablePresentation,
  IZcap
} from './types'

/**
 * Freewallet's JSON-LD document loader for presentation and credential
 * signing: the standard security contexts plus the BYOE App Connect context,
 * registered here (not bundled in the security loader) so BYOE vocabulary
 * additions ship with a `byoe-context` bump alone. Exported so single-VC
 * issuance (`src/lib/loginCredential.ts`) reuses the same context resolution
 * the VP compose path uses.
 */
const loader = securityLoader({ fetchRemoteContexts: true })
for (const [url, context] of byoeContexts) {
  loader.addStatic(url, context)
}
export const documentLoader = loader.build()

/**
 * The bare DID method name of the wallet's own did:key holder -- the one
 * every session can present, and the last arm of the dispatch.
 */
const DID_KEY_METHOD = 'key'

/**
 * The bare method names of the account's two published holder forms, in the
 * order the dispatch prefers them: the account's own did:webvh id, then the
 * did:web projection of the same document.
 */
const ACCOUNT_DID_METHODS = ['webvh', 'web'] as const

/**
 * The account key this session could sign a DIDAuth proof with, as the
 * multibase the account document would list it under, or `undefined` when the
 * session holds neither. The enrolled client's own key comes first: the
 * KMS-held key is custodied by the storage host by default, so it signs only
 * where no client key of this session's exists in the document.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Array<{ multibase: string; kms: boolean }>}
 */
function accountSigningCandidates({
  session
}: {
  session: Session
}): Array<{ multibase: string; kms: boolean }> {
  const { keyAgent, kmsAuthentication, keystoreAgent } = session.profile
  const candidates: Array<{ multibase: string; kms: boolean }> = []
  if (keyAgent?.id?.startsWith('did:key:')) {
    candidates.push({
      multibase: clientSigningKeyMultibase({ keyAgent }),
      kms: false
    })
  }
  if (kmsAuthentication && keystoreAgent) {
    candidates.push({
      multibase: multibaseOf(kmsAuthentication.vmId),
      kms: true
    })
  }
  return candidates
}

/**
 * The account key this session can present a did:webvh or did:web holder
 * with: a verification method the account's VERIFIED document lists under
 * `authentication` whose key this session holds a signer for, beside the
 * account DID that document resolves as.
 *
 * It is a cache read of the session's verified-log memo
 * (`src/session/verifiedLog.ts`) and nothing else. It resolves no log, issues
 * no request, and never throws: a cold memo, a failed verification, and a
 * session with no promoted pointer all answer `undefined`, and the dispatch
 * then presents the wallet's did:key. That is fail-closed in the right
 * direction -- the worst outcome is a did:key holder where an account form was
 * available -- and it is what keeps the dispatch safe inside the CHAPI approve
 * handler, which cannot survive a fetch that throws.
 *
 * The key map is deliberately not evidence: `key-map/keys.json` is written on
 * paths that never edit the account document, so a recorded binding is not a
 * published verification method.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {{ multibase: string; kms: boolean; accountDid: string } |
 *   undefined}
 */
function presentableAccountKey({
  session
}: {
  session: Session
}): { multibase: string; kms: boolean; accountDid: string } | undefined {
  const pointer = session.profile.accountPointer
  if (!pointer || !isWebvhDid(pointer.did)) {
    return undefined
  }
  const verified = peekVerifiedAccountLog({ profile: session.profile })
  if (!verified) {
    return undefined
  }
  try {
    const published = new Set(
      relationIds(verified.doc.authentication).map(id => multibaseOf(id))
    )
    const candidate = accountSigningCandidates({ session }).find(
      ({ multibase }) => published.has(multibase)
    )
    return (
      candidate && {
        ...candidate,
        accountDid: session.profile.didWebvh?.did ?? pointer.did
      }
    )
  } catch {
    // A key or a published id this session cannot parse into a multibase.
    // Answering `undefined` presents the wallet's did:key, which is the
    // fail-closed direction and the documented contract of this function.
    return undefined
  }
}

/**
 * The bare DID method names this session can present a holder for, as
 * `acceptedMethods` states them. Always carries `key`; carries `webvh` and
 * `web` when the account's verified document lists a key this session can
 * sign with. Fed to `didAuthMethodSupported` by the CHAPI popup's post-login
 * gate, so the refusal and the dispatch answer the same question.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {string[]}
 */
export function presentableDidMethods({
  session
}: {
  session: Session
}): string[] {
  return presentableAccountKey({ session })
    ? [...ACCOUNT_DID_METHODS, DID_KEY_METHOD]
    : [DID_KEY_METHOD]
}

/**
 * Whether the routed session can present a holder form this request's
 * `DIDAuthentication` query accepts -- the CHAPI popup's post-login gate, as
 * a pure decision the page renders rather than computes. A request stating no
 * constraint is satisfiable whatever the session holds.
 *
 * An App Connect response VP holds as the client did:key by construction
 * (app-connect-spec `decisions/0004`), whatever the account publishes, so
 * that branch is judged against the did:key alone rather than against what
 * the session could otherwise present.
 *
 * @param options {object}
 * @param options.session {Session}   the session the login routed to
 * @param options.queries {IVPRQuery[]}   the request's queries
 * @param options.appConnect {boolean}   whether this is an App Connect
 *   request
 * @returns {boolean}
 */
export function didAuthHolderPresentable({
  session,
  queries,
  appConnect
}: {
  session: Session
  queries: IVPRQuery[]
  appConnect: boolean
}): boolean {
  return didAuthMethodSupported(
    queries,
    appConnect
      ? DEFAULT_PRESENTABLE_DID_METHODS
      : presentableDidMethods({ session })
  )
}

/**
 * The bare method names a `DIDAuthentication` query constrains the holder to,
 * or `undefined` when the request states no constraint. An absent, empty, or
 * malformed `acceptedMethods` is a constraint on nothing, and a malformed
 * entry inside a well-formed list is skipped rather than dereferenced.
 *
 * @param options {object}
 * @param options.queries {IVPRQuery[]}
 * @returns {string[] | undefined}
 */
function acceptedMethodsOf({
  queries
}: {
  queries: IVPRQuery[]
}): string[] | undefined {
  const didAuth = queries.find(query => query.type === 'DIDAuthentication') as
    { acceptedMethods?: unknown } | undefined
  const acceptedMethods = didAuth?.acceptedMethods
  if (!Array.isArray(acceptedMethods) || acceptedMethods.length === 0) {
    return undefined
  }
  const methods: string[] = []
  for (const entry of acceptedMethods) {
    const method = (entry as { method?: unknown } | null)?.method
    if (typeof method === 'string') {
      methods.push(method)
    }
  }
  return methods
}

/**
 * Resolves the authentication signer and the holder DID to name on the
 * response VP, dispatching on the DID method the request accepts. The arms, in
 * order:
 *
 * 1. `webvh`, when the request accepts it and the account form is presentable:
 *    holder = the account's did:webvh, verification method
 *    `<did:webvh>#<multibase>`;
 * 2. `web`, when the request accepts it and the account form is presentable:
 *    holder = the did:web projection id of the same document, verification
 *    method `<did:web>#<multibase>` -- the same key under the projected id;
 * 3. `key`, when the request accepts it: holder = the wallet's own did:key;
 * 4. unconstrained (`acceptedMethods` absent, not an array, or empty): arm 2
 *    when the account form is presentable, arm 3 otherwise;
 * 5. a constraint this session can present none of: arm 3's signer again. The
 *    refusal is the CHAPI popup's two-position gate over
 *    {@link presentableDidMethods}, before consent; two of this function's
 *    callers have no refusal surface -- the CHAPI store popup renders a
 *    thrown message raw, and the external-request delivery path resolves a
 *    signer it never uses -- so every account arm falls through to arm 3 on
 *    any throw (a pointer host that does not parse, a key that does not).
 *    Arm 3 itself is the one thing left that can throw here, for a session
 *    holding no key agent at all, which is no session this wallet builds.
 *
 * Arms 1 and 2 sign with the enrolled client's own account key when the
 * document lists one for this session, and with the KMS-held key only where it
 * does not: that key is custodied by the storage host by default.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.queries {IVPRQuery[]}   the request's queries; an empty array
 *   states no constraint
 * @returns {Promise<PresentationSigner>}
 */
export async function presentationSignerFor({
  session,
  queries
}: {
  session: Session
  queries: IVPRQuery[]
}): Promise<PresentationSigner> {
  // Built on demand rather than up front: the account arms never touch the
  // did:key signer, and a session that holds no key agent must not be asked
  // for one on a path that would not have used it.
  const didKeySigner = () => ({
    signer: session.profile.keyAgent!.getSigner(),
    holder: session.user.id
  })
  // The account arms, resolved inside one guard: a pointer whose host does
  // not parse as a URL is all it takes for the projection id to throw, and
  // this function has callers with no refusal surface. Anything the arms
  // cannot resolve falls through to arm 3.
  let resolved:
    | {
        accountKey: NonNullable<ReturnType<typeof presentableAccountKey>>
        holder: string
      }
    | undefined
  try {
    const accountKey = presentableAccountKey({ session })
    const pointer = session.profile.accountPointer
    const accepted = acceptedMethodsOf({ queries })
    const accountAccepted =
      !accepted ||
      accepted.some(method =>
        ACCOUNT_DID_METHODS.includes(
          method as (typeof ACCOUNT_DID_METHODS)[number]
        )
      )
    if (accountKey && pointer && accountAccepted) {
      // Arm 1 when `webvh` is accepted; arms 2 and 4 both present the
      // projection, which is the account document under its did:web id.
      const holder = accepted?.includes('webvh')
        ? accountKey.accountDid
        : didWebFromSpace({
            wasServerUrl: pointer.host,
            spaceId: pointer.spaceId
          })
      resolved = { accountKey, holder }
    }
  } catch {
    resolved = undefined
  }
  if (!resolved) {
    return didKeySigner()
  }
  const { accountKey, holder } = resolved
  const verificationMethodId = `${holder}#${accountKey.multibase}`

  if (accountKey.kms) {
    const kmsSigner = await kmsAuthenticationSigner({
      session,
      verificationMethodId
    })
    return kmsSigner ? { signer: kmsSigner, holder } : didKeySigner()
  }
  const base = session.profile.keyAgent!.getSigner() as {
    type?: string
    sign: (options: { data: Uint8Array }) => Promise<Uint8Array>
  }
  return {
    signer: {
      id: verificationMethodId,
      type: base.type ?? 'Ed25519VerificationKey2020',
      sign: base.sign.bind(base)
    } as unknown as PresentationSigner['signer'],
    holder
  }
}

/**
 * Creates a Verifiable Presentation for the requester.
 *
 * @param options {object}
 * @param options.session {Session} - The logged-in session; supplies the signer
 *   and holder DID.
 * @param options.queries {IVPRQuery[]} - The request's queries; the holder
 *   dispatch reads the `DIDAuthentication` query's `acceptedMethods` from
 *   them. An empty array states no constraint.
 * @param [options.holderOverride] {PresentationSigner} - Pins the holder and
 *   its signer, bypassing the dispatch. App Connect passes the client did:key,
 *   whose response VP holds as the client identity whatever the app accepts.
 * @param [options.selectedVCs] {IVerifiableCredential[]} - VCs the user chose
 *   to share (empty for a DID-Auth-only response).
 * @param [options.challenge] {string} - Required when DID Auth is requested.
 * @param [options.domain] {string} - Required when DID Auth is requested.
 * @param options.didAuthRequested {boolean} - Whether to sign the VP.
 * @param [options.cryptosuite] {string} - Negotiated cryptosuite; falls back to
 *   the wallet default (Ed25519Signature2020) when absent.
 * @param [options.zcaps] {IZcap[]} - Delegated capabilities to embed as the
 *   VP's `zcap` array (before signing, so a DIDAuth proof covers them).
 * @param [options.appConnect] {{ firstRun: boolean }} - App Connect response
 *   marker to embed (before signing, like the grants).
 * @returns {Promise<IVerifiablePresentation>}
 */
export async function composeVP({
  session,
  queries,
  holderOverride,
  selectedVCs = [],
  challenge,
  domain,
  didAuthRequested,
  cryptosuite,
  zcaps = [],
  appConnect
}: {
  session: Session
  queries: IVPRQuery[]
  holderOverride?: PresentationSigner
  selectedVCs?: IVerifiableCredential[]
  challenge?: string
  domain?: string
  didAuthRequested: boolean
  cryptosuite?: string
  zcaps?: IZcap[]
  appConnect?: { firstRun: boolean }
}): Promise<IVerifiablePresentation> {
  // Freewallet's stricter DID Auth rule: both `challenge` and `domain` are
  // required (the shared guard requires only `challenge`). Enforced here so the
  // replay-check invariant is preserved.
  if (didAuthRequested && !(challenge && domain)) {
    throw new Error('Both "challenge" and "domain" are required for DID Auth.')
  }

  const presentationSigner =
    holderOverride ?? (await presentationSignerFor({ session, queries }))

  return composeVp({
    presentationSigner,
    selectedVcs: selectedVCs,
    challenge,
    domain,
    didAuthRequested,
    cryptosuite,
    zcaps,
    appConnect,
    documentLoader
  })
}
