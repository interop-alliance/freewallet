/**
 * Two lifecycle signals every live session carries, beside the promises the
 * login mender block stamps.
 *
 * The disposal signal (`session.disposal`) aborts once the session is torn
 * down: a logout or an account switch, a CHAPI popup page's teardown, a
 * never-entered session released, and the forget and account-deletion
 * ceremonies just before their local wipe. Work that outlives the page that
 * started it checks it before each browser-local write and before it mutates
 * the session, so a torn-down session writes nothing back. A forgotten
 * browser's client-key record, for one, must not be written again after the
 * forget ceremony wiped it.
 *
 * The encounter gate (`session.encounterGate`) opens once the login mender
 * block's registry-writing registrations have reported, so a mend raised at a
 * read never interleaves with them. A session whose composition starts no
 * block (signup, the lobby, a guest) opens its gate at construction.
 *
 * The controllers and openers live in module-private maps, so a session
 * carries only the signal and the promise, and nothing outside this module
 * can abort or open them except through the functions below.
 */
import type { Session } from '@/types/auth'

const controllers = new WeakMap<AbortSignal, AbortController>()
const gateOpeners = new WeakMap<Session, () => void>()

/**
 * Mints a session's disposal signal. The controller behind it stays in this
 * module, reached through {@link disposeSession}.
 *
 * @returns {AbortSignal}
 */
export function sessionDisposalSignal(): AbortSignal {
  const controller = new AbortController()
  controllers.set(controller.signal, controller)
  return controller.signal
}

/**
 * Aborts a session's disposal signal. Idempotent, and a no-op on a session
 * that carries none (a test fixture).
 *
 * @param options {object}
 * @param options.session {object}   the session being torn down
 * @returns {void}
 */
export function disposeSession({
  session
}: {
  session: Pick<Session, 'disposal'>
}): void {
  controllers.get(session.disposal)?.abort()
}

/**
 * Whether a session has been torn down. A session carrying no signal (a test
 * fixture) reads as live.
 *
 * @param options {object}
 * @param options.session {object}
 * @returns {boolean}
 */
export function isSessionDisposed({
  session
}: {
  session: Pick<Session, 'disposal'>
}): boolean {
  return session.disposal?.aborted === true
}

/**
 * Stamps a freshly built session's encounter gate. When a mender block
 * follows, the gate stays shut until {@link openEncounterGateBehindBlock} or
 * {@link openEncounterGate} opens it; otherwise it opens now.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.blockFollows {boolean}   whether the composition will start
 *   a login mender block on this session
 * @returns {void}
 */
export function armEncounterGate({
  session,
  blockFollows
}: {
  session: Session
  blockFollows: boolean
}): void {
  let open: () => void = () => undefined
  session.encounterGate = new Promise<void>(resolve => {
    open = resolve
  })
  if (blockFollows) {
    gateOpeners.set(session, open)
  } else {
    open()
  }
}

/**
 * Opens a session's encounter gate now: the composition that armed it for a
 * block decided to start none. A no-op on a gate already open.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {void}
 */
export function openEncounterGate({ session }: { session: Session }): void {
  gateOpeners.get(session)?.()
  gateOpeners.delete(session)
}

/**
 * Opens a session's encounter gate once its `registryReady` has settled. The
 * block stamps `registryReady` and then calls this, so the gate exists before
 * the block's first registration runs and opens only behind the last
 * registry writer.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {void}
 */
export function openEncounterGateBehindBlock({
  session
}: {
  session: Session
}): void {
  const registryReady = session.registryReady ?? Promise.resolve()
  void registryReady.then(
    () => openEncounterGate({ session }),
    () => openEncounterGate({ session })
  )
}
