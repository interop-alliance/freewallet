# 0030: An agent's identity is the key it holds

- Status: accepted
- Date: 2026-09-27
- Driving work: FW-232, how a CLI agent gets a stable identity across
  grant requests.
- Affects: freewallet (the interaction-URL request page, the
  Applications page's agent rows); `@interop/did-cli`
  (`di was request-grant`).

## Context

The wallet knows an agent only by the grant `controller` it names, and
the Applications page groups agent rows by that controller. An App
Connect app gets a stable, wallet-custodied identity: a seed the wallet
mints, stores in `app-connections`, and re-delivers to a returning app
it matches on the CHAPI-attested origin. An agent reaches the wallet
through an interaction URL, which attests nothing about its sender.
Anyone can mint an exchange and send the user the link.

A seed carries everything granted to its DID: every zcap naming it as
`controller`, and its recipiency on every private collection it was
granted. Without an attested caller, the only check on a re-issue would
be the user reading the consent screen.

## Decision

An agent's stable identity is the did:key it holds and saves. The
wallet recognizes a returning agent by its `controller`, as the
Applications page already does, and custodies no key material for
agents. did-cli re-requests under a saved key rather than minting a new
one each run. A lost key means a new agent identity. The old row is
revoked like any other.

## Rejected Alternatives

- A wallet-minted, wallet-custodied seed for agents, re-issued on the
  user's choice at consent. With no attested caller, a re-issue hands the
  agent's existing grants to whoever sent the link. It also puts a
  long-lived seed into a process that leaks what it reads (decision
  0004).
- Filling the app-key credential's `origin` claim with a self-declared
  or wallet-minted agent id. The App Connect spec reserves that claim for
  an identifier the transport attests, and a matcher trusting it would
  match on request-supplied text.

## Consequences

- No wallet change is needed for a stable agent identity. The work is a
  did-cli reuse path.
- Key loss is not recoverable. A rebind that re-grants a lost key's
  scope to a new key, without re-issuing key material, stays available
  as a separate design if key loss turns out to matter.
- An agent that can host a resolvable DID gets a stable identity across
  machines through FW-34's confidential-client tier, not through wallet
  custody.

## Revisit Criteria

1. A non-browser transport attests its caller the way the CHAPI mediator
   attests a web origin, so the App Connect spec's transport note can be
   filled in. A wallet-custodied agent seed can then be designed against
   that attested identifier.
