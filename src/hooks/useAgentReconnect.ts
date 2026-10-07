import { useRef, useState } from 'react'
import { useAsyncLoad } from '@/hooks/useAsyncLoad'
import {
  agentsSignedByWithdrawnAuthority,
  declineAgents,
  reconnectAgents,
  type AffectedAgent,
  type AgentRestoreOutcome
} from '@/session/agentReconnect'
import { createLogger } from '@/lib/log'
import type { Session } from '@/types/auth'

const log = createLogger('fw:ui:agents')

/**
 * Where a ceremony's reconnect stands once it ran: still running, or done
 * with one outcome per ticked agent.
 */
export type AgentReconnectState =
  { status: 'running' } | { status: 'done'; agents: AgentRestoreOutcome[] }

/**
 * React hook for the agent list a ceremony's dialog shows: the connected
 * agents holding a grant the withdrawn keys signed, each ticked by default.
 *
 * `withdrawn` names the authority the ceremony withdraws: `key` identifies
 * the ceremony's subject (the client, the credential), and `keys` resolves
 * the withdrawn verification-method ids, which a credential's dialog reads
 * from the account log. The list loads once per `key`, and `loading` is
 * true until the agents for the current one have been read, so a caller
 * holds its confirm button until then. `runCeremony` wraps the ceremony:
 * it drops the last reconnect's notice, takes the owner's choice (the
 * ticked agents and the unticked agents' DIDs) before the ceremony, and
 * once the ceremony resolves starts the reconnect past the dialog closing.
 * The reconnect writes the decline marker on each unticked agent, then
 * restores the ticked agents and runs the Settings inbox pass, even with
 * none ticked, and keeps the outcome for the notice. A ceremony that fails
 * therefore leaves no decline marker. A ceremony that ends the session
 * cannot write the markers once it resolves, so it takes the choice with
 * `confirm`, which writes nothing, and writes the markers alone with
 * `decline`.
 * A listing that cannot be read is logged and lists nothing.
 *
 * @param options {object}
 * @param options.session {Session | null}
 * @param options.withdrawn {object | null}   the withdrawn authority; `null`
 *   while no dialog is open
 * @param options.withdrawn.key {string}
 * @param options.withdrawn.keys {Function}   `() => string[]` or
 *   `() => Promise<string[]>`
 * @returns {object}   the agents and whether they are still loading, the
 *   tick state and its toggle, `confirm`, `decline`, `runCeremony`, and the
 *   last reconnect's state
 */
export function useAgentReconnect({
  session,
  withdrawn
}: {
  session: Session | null | undefined
  withdrawn: { key: string; keys: () => string[] | Promise<string[]> } | null
}) {
  const withdrawnKey = withdrawn?.key ?? ''
  // The unticked DIDs, held against the subject they were chosen for, so a
  // dialog opened on another row starts with every agent ticked again.
  const [unticked, setUnticked] = useState<{ key: string; dids: string[] }>({
    key: '',
    dids: []
  })
  const [state, setState] = useState<AgentReconnectState | null>(null)
  // The reconnect run the notice belongs to; `clearState` retires it, so a
  // run still in flight then reports nothing.
  const runRef = useRef(0)
  const { data, loading } = useAsyncLoad(
    async () => {
      const keys = await withdrawn!.keys()
      return {
        key: withdrawnKey,
        agents: await agentsSignedByWithdrawnAuthority({
          session: session!,
          keys
        })
      }
    },
    // `withdrawn` is read through the loader, which useAsyncLoad holds in a
    // ref; its `key` is what decides a re-read.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [session, withdrawnKey],
    {
      enabled: !!session && withdrawn !== null,
      onError: err => {
        log.warn('Could not list the agents a ceremony would cut off', { err })
      }
    }
  )
  // A listing read for an earlier subject is not shown for this one.
  const agents: AffectedAgent[] =
    withdrawn !== null && data?.key === withdrawnKey ? data.agents : []
  const untickedNow = unticked.key === withdrawnKey ? unticked.dids : []

  const isTicked = (did: string): boolean => !untickedNow.includes(did)

  const toggle = (did: string): void => {
    setUnticked({
      key: withdrawnKey,
      dids: untickedNow.includes(did)
        ? untickedNow.filter(held => held !== did)
        : [...untickedNow, did]
    })
  }

  /**
   * Returns the owner's choice: the ticked agents, and the unticked
   * agents' DIDs. Writes nothing.
   *
   * @returns {{ ticked: AffectedAgent[], declined: string[] }}
   */
  const confirm = (): { ticked: AffectedAgent[]; declined: string[] } => ({
    ticked: agents.filter(agent => !untickedNow.includes(agent.did)),
    declined: agents
      .map(agent => agent.did)
      .filter(did => untickedNow.includes(did))
  })

  /**
   * Writes the decline marker on each unticked agent. Best-effort: a failed
   * marker is logged.
   *
   * @param options {object}
   * @param options.declined {string[]}   the unticked agents' DIDs
   * @returns {Promise<void>}
   */
  const decline = async ({
    declined
  }: {
    declined: string[]
  }): Promise<void> => {
    if (!session || declined.length === 0) {
      return
    }
    try {
      await declineAgents({ session, dids: declined })
    } catch (err) {
      log.warn('Could not record the declined agents', { err })
    }
  }

  /**
   * Runs once the ceremony resolved: writes the decline marker on each
   * unticked agent, then restores the ticked agents and runs the Settings
   * inbox pass. The notice shows only when some agent was ticked.
   *
   * @param options {object}
   * @param options.ticked {AffectedAgent[]}   the ticked agents `confirm`
   *   returned
   * @param options.declined {string[]}   the unticked agents' DIDs
   * @returns {Promise<void>}
   */
  const reconnect = async ({
    ticked,
    declined
  }: {
    ticked: AffectedAgent[]
    declined: string[]
  }): Promise<void> => {
    if (!session) {
      return
    }
    const run = ++runRef.current
    const names = new Map(ticked.map(agent => [agent.did, agent.name]))
    const named = (outcome: AgentRestoreOutcome): AgentRestoreOutcome => {
      const name = outcome.name ?? names.get(outcome.did)
      return name === undefined ? outcome : { ...outcome, name }
    }
    // Only the run the notice belongs to writes it.
    const report = (next: AgentReconnectState): void => {
      if (ticked.length > 0 && runRef.current === run) {
        setState(next)
      }
    }
    report({ status: 'running' })
    // The decline lands before the restore, so a restore that fails leaves
    // the owner's choice recorded on every unticked entry.
    await decline({ declined })
    try {
      const result = await reconnectAgents({
        session,
        dids: ticked.map(agent => agent.did)
      })
      report({ status: 'done', agents: result.agents.map(named) })
    } catch (err) {
      log.warn('Could not reconnect the ticked agents', { err })
      report({
        status: 'done',
        agents: ticked.map(agent =>
          named({
            did: agent.did,
            outcome: 'not-restored',
            reason: 'record-failed'
          })
        )
      })
    }
  }

  const clearState = (): void => {
    runRef.current += 1
    setState(null)
  }

  /**
   * Runs a ceremony between the owner's choice and the reconnect: drops the
   * last notice, takes the choice, awaits the ceremony, and once it
   * resolves starts the reconnect without waiting on it. A ceremony that
   * throws starts no reconnect, so it leaves no decline marker.
   *
   * @param ceremony {Function}   `() => Promise<T>`
   * @returns {Promise<T>}   the ceremony's result
   */
  const runCeremony = async <T>(ceremony: () => Promise<T>): Promise<T> => {
    clearState()
    const choice = confirm()
    const result = await ceremony()
    void reconnect(choice)
    return result
  }

  return {
    agents,
    loading,
    isTicked,
    toggle,
    confirm,
    decline,
    runCeremony,
    state
  }
}
