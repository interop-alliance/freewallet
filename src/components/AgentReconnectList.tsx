/**
 * The agent list a ceremony's dialog shows, and the notice its reconnect
 * leaves. The list names the connected agents holding a grant the ceremony's
 * withdrawn keys signed. In `tick` mode each carries a checkbox, ticked by
 * default, and the copy says the ticked agents' subscribers are reconnected.
 * `next-sign-in` mode is the last-client transition's, which ends this
 * browser's session, so the ticked agents are offered again at a later
 * sign-in. `ends` mode is the ordinary forget's: no tick, and the copy says
 * their access ends. An empty list renders nothing.
 */
import Alert from '@mui/material/Alert'
import Checkbox from '@mui/material/Checkbox'
import FormControlLabel from '@mui/material/FormControlLabel'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import type { AffectedAgent } from '@/session/agentReconnect'
import type { AgentReconnectState } from '@/hooks/useAgentReconnect'

/**
 * The display name of an agent: its name, else its DID.
 *
 * @param agent {{ did: string, name?: string }}
 * @returns {string}
 */
function agentLabel(agent: { did: string; name?: string }): string {
  return agent.name ?? agent.did
}

/**
 * The list.
 *
 * @param options {object}
 * @param options.agents {AffectedAgent[]}
 * @param options.mode {'tick' | 'next-sign-in' | 'ends'}
 * @param options.isTicked {Function}   `(did) => boolean`
 * @param options.onToggle {Function}   `(did) => void`
 * @param [options.disabled] {boolean}
 */
export function AgentReconnectList({
  agents,
  mode,
  isTicked,
  onToggle,
  disabled = false
}: {
  agents: AffectedAgent[]
  mode: 'tick' | 'next-sign-in' | 'ends'
  isTicked: (did: string) => boolean
  onToggle: (did: string) => void
  disabled?: boolean
}) {
  const { t } = useTranslation()
  if (agents.length === 0) {
    return null
  }
  const introKey = {
    tick: 'settings.agentReconnect.intro',
    'next-sign-in': 'settings.agentReconnect.introNextSignIn',
    ends: 'settings.agentReconnect.introEnds'
  }[mode]
  return (
    <Stack sx={{ gap: 0.5, mt: 1 }} data-testid="agent-reconnect-list">
      <Typography variant="body2">{t(introKey)}</Typography>
      {agents.map(agent =>
        mode === 'ends' ? (
          <Typography
            key={agent.did}
            variant="body2"
            sx={{ wordBreak: 'break-all', pl: 1 }}
          >
            {agentLabel(agent)}
          </Typography>
        ) : (
          <FormControlLabel
            key={agent.did}
            control={
              <Checkbox
                size="small"
                checked={isTicked(agent.did)}
                disabled={disabled}
                onChange={() => onToggle(agent.did)}
                slotProps={{
                  input: { 'aria-label': agentLabel(agent) }
                }}
              />
            }
            label={agentLabel(agent)}
            sx={{ wordBreak: 'break-all' }}
          />
        )
      )}
    </Stack>
  )
}

/**
 * The notice a reconnect leaves: running, then done, naming any agent it
 * could not restore. Renders nothing before a reconnect with a ticked agent
 * ran.
 *
 * @param options {object}
 * @param options.state {AgentReconnectState | null}
 */
export function AgentReconnectNotice({
  state
}: {
  state: AgentReconnectState | null
}) {
  const { t } = useTranslation()
  if (state === null) {
    return null
  }
  if (state.status === 'running') {
    return (
      <Alert severity="info" data-testid="agent-reconnect-notice">
        {t('settings.agentReconnect.running')}
      </Alert>
    )
  }
  const failed = state.agents.filter(agent => agent.outcome !== 'restored')
  return (
    <Stack sx={{ gap: 1 }} data-testid="agent-reconnect-notice">
      {failed.length < state.agents.length && (
        <Alert severity="success">{t('settings.agentReconnect.done')}</Alert>
      )}
      {failed.length > 0 && (
        <Alert severity="warning">
          {t('settings.agentReconnect.notRestored', {
            names: failed.map(agentLabel).join(', ')
          })}
        </Alert>
      )}
    </Stack>
  )
}
