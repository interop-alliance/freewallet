# 0029: App keys do not migrate with the content

- Status: accepted
- Date: 2026-09-17
- Driving work: the design for migrating a backup bundle's content into
  a new account, which had to decide whether the `app-connections`
  collection is content.
- Affects: freewallet (the sink counts `app-connections` rows and calls
  no import function for them; `StorageManager.addCredential` keeps
  refusing the app-key marker type); dcw (the same); the App Connect
  documentation, which says a connected app must be added again after a
  migration.

## Context

An app key is a self-issued credential holding a 32-byte seed that
exists only in the wallet and the app, bound to a requesting origin and
the app's canonical URL. On the next App Connect to that origin the
wallet matches a returning app by the marker type, the `appUrl`, the
origin, and the seed-to-subject binding, and answers with capabilities
delegated to the seed's did:key plus epoch recipiency on the app's
collections. The only write path today is the mint path's own function,
which screens provenance not at all, and `addCredential` refuses every
externally supplied credential carrying the marker type.

A bundle is text its author chose. A planted app key that binds
perfectly would, on the victim's next App Connect to that origin, be
matched first and receive the delegated capabilities and epoch
recipiency. was-react's reconnect continuity check refuses renewed
grants that name a different Space, so a carried key does not even let
the app reconnect without re-adding.

## Decision

The migration does not carry `app-connections`. Its rows are counted in
the report and no import function is called. Every connected app and
agent is added again from scratch on the new account, and the entry
page says so. `addCredential`'s refusal of the marker type stands.

## Rejected Alternatives

- Carrying app keys through the mint path's function. It screens
  nothing, so a planted key lands as the user's own.
- A third write path with a stated provenance rule. The rule needs
  verified bundle provenance to rest on, which does not exist yet.

## Consequences

- A user who migrates re-adds every app and agent.
- The app-provisioned collections those keys addressed stay out of the
  migration with them.

## Revisit Criteria

1. Bundle provenance verifies end to end, so a carried key's origin is
   evidence; a provenance-gated import function can then be designed,
   together with the `addCredential` refusal it must amend.
2. The app-side reconnect continuity rule changes so that a carried key
   is useful without re-adding.
