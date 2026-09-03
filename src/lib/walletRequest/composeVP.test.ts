// @vitest-environment node
import { describe, it, expect, beforeAll, vi } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'
import { clientSigningKeyMultibase } from '@interop/wallet-core/webvh'
import type { IVPRQuery } from '@interop/wallet-core/request'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import type { Session } from '@/types/auth'
import {
  inMemorySessionPersistence,
  transientSessionStores
} from '@/session/persistence'
import { createVerifiedLogCache } from '@/session/verifiedLog'
import {
  composeVP,
  didAuthHolderPresentable,
  presentableDidMethods,
  presentationSignerFor
} from './composeVP'

/**
 * Signing-path tests for the App Connect response marker: the `appConnect`
 * member is defined by the hosted App Connect context appended to the VP
 * `@context`, and the DIDAuth proof must canonicalize (safe mode) and cover it
 * rather than reject it.
 *
 * Plus the transient session's response identity (FW-203, over
 * app-connect-spec `decisions/0004`): the VP's `holder` and its DIDAuth
 * `proof.verificationMethod` are the visit key's BARE did:key forms. The
 * `<clientAnnexDid>#<vm>` form belongs to WAS invocations alone, and the
 * app-side loader has to be able to resolve what it reads here.
 *
 * Plus the three-way holder dispatch (FW-344) at the bottom of this file: the
 * holder form follows the request's `acceptedMethods`, over a presentability
 * predicate that reads the session's verified account document and nothing
 * else.
 */

const CHALLENGE = 'test-challenge-123'
const DOMAIN = 'https://app.example'
const APP_CONNECT_CONTEXT_URL = 'https://w3id.org/byoe/app-connect/v1'

let session: Session

beforeAll(async () => {
  const keyAgent = await CapabilityAgent.fromSecret({
    secret: new Uint8Array(32).fill(7),
    handle: 'test'
  })
  session = {
    user: { id: keyAgent.id },
    profile: { keyAgent }
  } as unknown as Session
})

describe('composeVP with an appConnect marker', () => {
  it('embeds the marker and its context term on a signed VP', async () => {
    const presentation = (await composeVP({
      session,
      queries: [],
      didAuthRequested: true,
      challenge: CHALLENGE,
      domain: DOMAIN,
      appConnect: { firstRun: true }
    })) as { appConnect?: unknown; '@context': unknown; proof?: unknown }

    expect(presentation.appConnect).toEqual({ firstRun: true })
    const contexts = presentation['@context'] as Array<string | object>
    expect(contexts).toContain(APP_CONNECT_CONTEXT_URL)
    expect(presentation.proof).toBeDefined()
  })

  it('embeds the marker on an unsigned VP', async () => {
    const presentation = (await composeVP({
      session,
      queries: [],
      didAuthRequested: false,
      selectedVCs: [
        {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential'],
          issuer: session.user.id,
          credentialSubject: { id: session.user.id }
        } as never
      ],
      appConnect: { firstRun: false }
    })) as { appConnect?: unknown; proof?: unknown }

    expect(presentation.appConnect).toEqual({ firstRun: false })
    expect(presentation.proof).toBeUndefined()
  })

  it('omits the marker and term when appConnect is absent', async () => {
    const presentation = (await composeVP({
      session,
      queries: [],
      didAuthRequested: true,
      challenge: CHALLENGE,
      domain: DOMAIN
    })) as { appConnect?: unknown; '@context': unknown }

    expect(presentation.appConnect).toBeUndefined()
    const contexts = presentation['@context'] as Array<string | object>
    expect(contexts).not.toContain(APP_CONNECT_CONTEXT_URL)
  })
})

describe('composeVP from a transient session', () => {
  const CLIENT_ANNEX_DID = 'did:webvh:QmAnnexScid:example.com:annex-space:id'
  let transient: Session

  beforeAll(async () => {
    const keyAgent = await CapabilityAgent.fromSecret({
      secret: new Uint8Array(32).fill(9),
      handle: 'transient-visit'
    })
    // The shape `transientSessionFromKeyringHit` assembles: a per-visit key
    // agent, the annex identity declared on the persistence strategy (rather
    // than on the profile's signing identity), and no account pointer -- so
    // the presentability predicate is false for this session and the account
    // arms of `presentationSignerFor` are out of reach.
    transient = {
      user: { id: keyAgent.id },
      profile: {
        keyAgent,
        persistence: inMemorySessionPersistence({
          stores: transientSessionStores(),
          clientAnnex: {
            clientAnnexDid: CLIENT_ANNEX_DID,
            invocationCapability: { id: 'urn:zcap:generation' } as never
          }
        })
      }
    } as unknown as Session
  })

  it('holds as the did:key on a promoted account the visit key is unlisted in', async () => {
    // The realistic transient shape: the account IS promoted and its log is
    // verified this visit, but the per-visit key lives in the client annex,
    // which the account document never lists. So no account holder form is
    // presentable and the response holds as the visit key's did:key.
    const keyAgent = await CapabilityAgent.fromSecret({
      secret: new Uint8Array(32).fill(21),
      handle: 'transient-visit-promoted'
    })
    const spaceId = 'spaceTransient'
    const accountDid = `did:webvh:QmScidT:was.example.test:space:${spaceId}:id`
    const pointer = {
      did: accountDid,
      spaceId,
      host: 'https://was.example.test'
    }
    const cache = createVerifiedLogCache({
      pinStore: memoryResourceLogPinStore()
    })
    cache.prime({
      pointer,
      verified: {
        doc: {
          id: accountDid,
          // Another client's key, and the credential's ladder VM: neither is
          // this visit's.
          authentication: [`${accountDid}#z6MkAnotherEnrolledClient`]
        },
        log: [],
        updateKeys: [],
        nextKeyHashes: []
      } as never
    })
    const promotedTransient = {
      user: { id: keyAgent.id },
      profile: {
        keyAgent,
        accountPointer: pointer,
        didWebvh: { did: accountDid },
        verifiedLog: cache,
        persistence: inMemorySessionPersistence({
          stores: transientSessionStores(),
          clientAnnex: {
            clientAnnexDid: CLIENT_ANNEX_DID,
            invocationCapability: { id: 'urn:zcap:generation' } as never
          }
        })
      }
    } as unknown as Session

    const { holder, signer } = await presentationSignerFor({
      session: promotedTransient,
      queries: []
    })

    expect(holder).toBe(promotedTransient.user.id)
    expect(signer.id?.startsWith(`${promotedTransient.user.id}#`)).toBe(true)
    expect(presentableDidMethods({ session: promotedTransient })).toEqual([
      'key'
    ])
  })

  it("holds and signs as the visit key's bare did:key, not the annex form", async () => {
    const presentation = (await composeVP({
      session: transient,
      queries: [],
      didAuthRequested: true,
      challenge: CHALLENGE,
      domain: DOMAIN,
      appConnect: { firstRun: true }
    })) as {
      holder?: string
      proof?: { verificationMethod?: string }
    }

    expect(presentation.holder).toBe(transient.user.id)
    expect(transient.user.id.startsWith('did:key:')).toBe(true)
    const verificationMethod = presentation.proof?.verificationMethod ?? ''
    expect(verificationMethod.startsWith(`${transient.user.id}#`)).toBe(true)
    expect(presentation.holder).not.toContain(CLIENT_ANNEX_DID)
    expect(verificationMethod).not.toContain(CLIENT_ANNEX_DID)
  })
})

/**
 * The three-way holder dispatch (FW-344). The response VP's holder and its
 * DIDAuth `verificationMethod` follow the request's `acceptedMethods`: the
 * account's did:webvh, the did:web projection of the same document, or the
 * wallet's own did:key. Presentability is read from the session's verified-log
 * memo, so a stamped KMS binding the document does not publish, and a cold
 * memo, both fall back to did:key rather than signing under a verification
 * method no resolver would find.
 */
describe('the DIDAuth holder dispatch', () => {
  const HOST = 'https://was.example.test'
  const SPACE_ID = 'spaceAbc'
  const ACCOUNT_DID = `did:webvh:QmScid:was.example.test:space:${SPACE_ID}:id`
  const PROJECTION_DID = `did:web:was.example.test:space:${SPACE_ID}:id`
  const KMS_MULTIBASE = 'z6MkKmsAuthenticationKeyMultibase'

  let clientMultibase: string
  let promotedSession: Session

  /**
   * A session on a promoted account whose verified-log memo is primed with a
   * document listing `authenticationMultibases` under `authentication`.
   * `verifiedLog: false` leaves the memo cold, the offline / mid-ceremony
   * state the predicate must answer `undefined` for.
   */
  async function accountSession({
    authenticationMultibases,
    kmsAuthentication = false,
    verifiedLog = true
  }: {
    authenticationMultibases: string[]
    kmsAuthentication?: boolean
    verifiedLog?: boolean
  }): Promise<Session> {
    const keyAgent = await CapabilityAgent.fromSecret({
      secret: new Uint8Array(32).fill(11),
      handle: 'promoted-client'
    })
    const pointer = { did: ACCOUNT_DID, spaceId: SPACE_ID, host: HOST }
    const cache = createVerifiedLogCache({
      pinStore: memoryResourceLogPinStore()
    })
    if (verifiedLog) {
      cache.prime({
        pointer,
        verified: {
          doc: {
            id: ACCOUNT_DID,
            authentication: authenticationMultibases.map(
              multibase => `${ACCOUNT_DID}#${multibase}`
            )
          },
          log: [],
          updateKeys: [],
          nextKeyHashes: []
        } as never
      })
    }
    return {
      user: { id: keyAgent.id },
      profile: {
        keyAgent,
        accountPointer: pointer,
        didWebvh: { did: ACCOUNT_DID },
        verifiedLog: cache,
        ...(kmsAuthentication && {
          // Enough of a KeystoreAgent for `kmsAuthenticationSigner`: the
          // handle is constructed locally, with no round trip, and the
          // dispatch is asserted on the signer's id rather than its bytes.
          keystoreAgent: {
            getAsymmetricKey: async () => ({
              sign: async () => new Uint8Array(64)
            })
          } as never,
          kmsAuthentication: {
            vmId: `${PROJECTION_DID}#${KMS_MULTIBASE}`,
            kmsKeyId: 'urn:kms:key:1'
          }
        })
      }
    } as unknown as Session
  }

  /**
   * A `DIDAuthentication` query constrained to these bare method names.
   */
  function didAuthQuery(methods: string[]): IVPRQuery[] {
    return [
      {
        type: 'DIDAuthentication',
        acceptedMethods: methods.map(method => ({ method }))
      }
    ] as unknown as IVPRQuery[]
  }

  beforeAll(async () => {
    const keyAgent = await CapabilityAgent.fromSecret({
      secret: new Uint8Array(32).fill(11),
      handle: 'promoted-client'
    })
    clientMultibase = clientSigningKeyMultibase({ keyAgent })
    promotedSession = await accountSession({
      authenticationMultibases: [clientMultibase]
    })
  })

  it('presents the projection id when the request states no constraint', async () => {
    const { holder, signer } = await presentationSignerFor({
      session: promotedSession,
      queries: []
    })

    expect(holder).toBe(PROJECTION_DID)
    expect(signer.id).toBe(`${PROJECTION_DID}#${clientMultibase}`)
  })

  it('presents the projection id for an empty acceptedMethods', async () => {
    const { holder } = await presentationSignerFor({
      session: promotedSession,
      queries: didAuthQuery([])
    })

    expect(holder).toBe(PROJECTION_DID)
  })

  it('presents the account did:webvh when webvh is accepted', async () => {
    const { holder, signer } = await presentationSignerFor({
      session: promotedSession,
      queries: didAuthQuery(['webvh'])
    })

    expect(holder).toBe(ACCOUNT_DID)
    expect(signer.id).toBe(`${ACCOUNT_DID}#${clientMultibase}`)
  })

  it('presents the projection id when web is accepted', async () => {
    const { holder, signer } = await presentationSignerFor({
      session: promotedSession,
      queries: didAuthQuery(['web'])
    })

    expect(holder).toBe(PROJECTION_DID)
    expect(signer.id).toBe(`${PROJECTION_DID}#${clientMultibase}`)
  })

  it('presents the did:key when key is the only accepted method', async () => {
    const { holder, signer } = await presentationSignerFor({
      session: promotedSession,
      queries: didAuthQuery(['key'])
    })

    expect(holder).toBe(promotedSession.user.id)
    expect(signer.id).toBe(`${promotedSession.user.id}#${clientMultibase}`)
  })

  it('takes the first presentable method in webvh, web, key order', async () => {
    const { holder } = await presentationSignerFor({
      session: promotedSession,
      queries: didAuthQuery(['key', 'webvh'])
    })

    expect(holder).toBe(ACCOUNT_DID)
  })

  it('falls back to the did:key for a constraint it cannot present', async () => {
    const { holder } = await presentationSignerFor({
      session: promotedSession,
      queries: didAuthQuery(['ion'])
    })

    // The refusal is the popup's gate, before consent; the dispatch itself
    // resolves a signer rather than throwing (the external-request delivery
    // path resolves one it never uses).
    expect(holder).toBe(promotedSession.user.id)
  })

  it('signs as the KMS key only where the document lists no client key', async () => {
    const session = await accountSession({
      authenticationMultibases: [KMS_MULTIBASE],
      kmsAuthentication: true
    })

    const { holder, signer } = await presentationSignerFor({
      session,
      queries: didAuthQuery(['web'])
    })

    expect(holder).toBe(PROJECTION_DID)
    expect(signer.id).toBe(`${PROJECTION_DID}#${KMS_MULTIBASE}`)
  })

  it("prefers the client's own account key over the KMS-held one", async () => {
    const session = await accountSession({
      authenticationMultibases: [clientMultibase, KMS_MULTIBASE],
      kmsAuthentication: true
    })

    const { signer } = await presentationSignerFor({
      session,
      queries: didAuthQuery(['webvh'])
    })

    expect(signer.id).toBe(`${ACCOUNT_DID}#${clientMultibase}`)
  })

  it('takes the did:key arm for a KMS binding the document does not list', async () => {
    // The key map records a binding on paths that never edit the document, so
    // a stamped binding is not evidence of a published verification method.
    const session = await accountSession({
      authenticationMultibases: [],
      kmsAuthentication: true
    })

    const { holder } = await presentationSignerFor({
      session,
      queries: didAuthQuery(['web'])
    })

    expect(holder).toBe(session.user.id)
  })

  it('takes the did:key arm on a cold memo, without fetching', async () => {
    const session = await accountSession({
      authenticationMultibases: [clientMultibase],
      verifiedLog: false
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    const { holder } = await presentationSignerFor({
      session,
      queries: []
    })

    expect(holder).toBe(session.user.id)
    expect(fetchSpy).not.toHaveBeenCalled()
    fetchSpy.mockRestore()
  })

  it('takes the did:key arm when the pointer host does not parse', async () => {
    // The projection id is built with `new URL(pointer.host)`, which throws
    // on a host a served record could carry. Every account arm fails closed
    // to the did:key rather than escaping into a caller with no refusal
    // surface.
    const session = await accountSession({
      authenticationMultibases: [clientMultibase]
    })
    session.profile.accountPointer = {
      ...session.profile.accountPointer!,
      host: 'not a url'
    }
    // The memo is keyed on the pointer, so re-prime it under the broken one.
    session.profile.verifiedLog!.prime({
      pointer: session.profile.accountPointer as never,
      verified: {
        doc: {
          id: ACCOUNT_DID,
          authentication: [`${ACCOUNT_DID}#${clientMultibase}`]
        },
        log: [],
        updateKeys: [],
        nextKeyHashes: []
      } as never
    })

    const { holder } = await presentationSignerFor({
      session,
      queries: []
    })

    expect(holder).toBe(session.user.id)
  })

  it('takes the did:key arm when the memo holds another account', async () => {
    // What a failed verification leaves behind, and what a memo taken against
    // a pointer this session has since moved off looks like.
    const session = await accountSession({
      authenticationMultibases: [clientMultibase]
    })
    session.profile.verifiedLog!.invalidate()

    const { holder } = await presentationSignerFor({
      session,
      queries: didAuthQuery(['webvh'])
    })

    expect(holder).toBe(session.user.id)
  })

  it('pins the App Connect response VP to the client did:key', async () => {
    // App Connect passes an explicit holder override, so the dispatch never
    // runs there whatever the app's `acceptedMethods` says.
    const presentation = (await composeVP({
      session: promotedSession,
      queries: didAuthQuery(['webvh']),
      holderOverride: {
        signer: promotedSession.profile.keyAgent!.getSigner(),
        holder: promotedSession.user.id
      },
      didAuthRequested: true,
      challenge: CHALLENGE,
      domain: DOMAIN,
      appConnect: { firstRun: true }
    })) as { holder?: string; proof?: { verificationMethod?: string } }

    expect(presentation.holder).toBe(promotedSession.user.id)
    expect(presentation.proof?.verificationMethod).toBe(
      `${promotedSession.user.id}#${clientMultibase}`
    )
  })
})

/**
 * The presentable-method set the CHAPI popup's post-login gate reads. It must
 * answer the same question the dispatch does, from the same memo.
 */
describe('presentableDidMethods', () => {
  it('reports did:key alone for a session with no account pointer', async () => {
    const keyAgent = await CapabilityAgent.fromSecret({
      secret: new Uint8Array(32).fill(13),
      handle: 'unpromoted'
    })
    const session = {
      user: { id: keyAgent.id },
      profile: { keyAgent }
    } as unknown as Session

    expect(presentableDidMethods({ session })).toEqual(['key'])
  })
})

/**
 * The CHAPI get page's post-login gate, as the pure decision the page
 * renders. A false answer is what puts the block screen where the consent
 * panel would go, with no step added between the login and the block.
 */
describe('didAuthHolderPresentable', () => {
  let kmsLessSession: Session

  beforeAll(async () => {
    const keyAgent = await CapabilityAgent.fromSecret({
      secret: new Uint8Array(32).fill(17),
      handle: 'kms-less'
    })
    kmsLessSession = {
      user: { id: keyAgent.id },
      profile: { keyAgent }
    } as unknown as Session
  })

  /**
   * A `DIDAuthentication` query constrained to these bare method names.
   */
  function query(methods: string[]): IVPRQuery[] {
    return [
      {
        type: 'DIDAuthentication',
        acceptedMethods: methods.map(method => ({ method }))
      }
    ] as unknown as IVPRQuery[]
  }

  it('refuses a webvh-only request from a session that can present did:key', () => {
    expect(
      didAuthHolderPresentable({
        session: kmsLessSession,
        queries: query(['webvh']),
        appConnect: false
      })
    ).toBe(false)
  })

  it('admits a request stating no constraint', () => {
    expect(
      didAuthHolderPresentable({
        session: kmsLessSession,
        queries: [{ type: 'DIDAuthentication' }] as unknown as IVPRQuery[],
        appConnect: false
      })
    ).toBe(true)
  })

  it('admits a did:key request', () => {
    expect(
      didAuthHolderPresentable({
        session: kmsLessSession,
        queries: query(['key']),
        appConnect: false
      })
    ).toBe(true)
  })

  it('judges an App Connect request against the client did:key alone', () => {
    // Whatever the account publishes: an App Connect response VP holds as
    // the client did:key by construction.
    expect(
      didAuthHolderPresentable({
        session: kmsLessSession,
        queries: query(['key']),
        appConnect: true
      })
    ).toBe(true)
    expect(
      didAuthHolderPresentable({
        session: kmsLessSession,
        queries: query(['webvh']),
        appConnect: true
      })
    ).toBe(false)
  })
})
