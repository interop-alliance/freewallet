# 0004: Agents are grantees, never wallet clients

- Status: accepted
- Date: 2026-08-22
- Driving work: the agent storage demo (FW-227), where a CLI LLM agent
  publishes to a public collection in the user's Space.
- Affects: freewallet (`src/lib/walletRequest/`, the request page at
  `/external/request`, the Applications page), `@interop/did-cli`
  (`di was request-grant`), the Claude Code skill.

## Context

An LLM agent is a third-party process on the user's machine. It leaks
what it reads: keys and passphrases in its context end up in transcripts
and logs. The wallet has two places a third party can stand: as a wallet
client (enrolled in the account document, or a per-visit transient client
in the client annex, both holding the user key and the account's full
authority) or as a grantee (a foreign controller holding delegated,
attenuated, expiring, revocable zcaps). Transient login was recently built
and looks reusable for an agent.

## Decision

An agent is a grantee. It mints its own key, names itself as the
`controller` of a standalone `AuthorizationCapabilityQuery`, and receives
zcaps through the wallet's grant engine. It is never given the unlock
credential, never enrolled in the account document or the client annex,
and never holds the user key. The glossary term "agent" names this class
only. A future CLI-class wallet is a wallet client and is not called an
agent.

## Rejected Alternatives

- The agent as a transient wallet client: requires handing the agent the
  passphrase; gives it the whole vault; consent is all-or-nothing with no
  collection scope, verb limit, or TTL shorter than the generation's GC;
  provenance reads "a client of the account" rather than "agent X under a
  grant from Y".
- The agent as an App Connect app with a wallet-minted seed: unsatisfiable
  off-CHAPI (no attested origin) and hands the agent a long-lived seed.
  Deferred, not rejected: a native client class may make it right later.

## Consequences

The agent gets only what the grant engine can delegate on the origin-less
entry point: the public and app-provisioned collection verb sets, with a
7-day write TTL; shares, whole-Space reads, and protected-collection reads
are refused there. It has no stable identity until a persistence story
lands (a saved did-cli key, or a native client class). Standalone grants
are invisible to the Applications page until that surface grows a row for
them (FW-230).

## Revisit Criteria

1. A CLI-class wallet ships and users want an agent to drive it on their
   behalf. The answer is still a grant from that wallet to the agent, not
   the agent becoming the wallet.
2. A signing-oracle custody model makes an agent-held wallet credential not
   leak into context. Even then, reopen as a new flow with its own consent
   surface, not by reusing the transient login.
