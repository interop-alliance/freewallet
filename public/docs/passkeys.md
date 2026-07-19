# Passkeys

A **passkey** lets you unlock your Freewallet with your device's biometric or
screen lock (Touch ID, Face ID, Windows Hello, a security key) instead of
typing your passphrase. You can sign up with a passkey, log in with one, and
add or remove passkeys from Settings.

## What a passkey is (and is not) in Freewallet

- **A passkey is a peer unlock method, not a second factor.** It is an
  alternative to your passphrase, with the same authority: any unlock method
  grants full control of the wallet. A passkey does not add a step on top of
  the passphrase; it stands in for it.
- **It is phishing-resistant.** A passkey is bound to this wallet's web origin,
  so it cannot be replayed on a look-alike site the way a typed passphrase can.
  This makes passkey login strictly stronger than the passphrase against
  phishing.
- **There is no server checking your passkey.** Freewallet has no login server
  and stores no record of your passkey. Every unlock method is anchored to a
  secret only you can produce; the passkey's secret is the output of the
  WebAuthn **PRF extension**, a per-credential value your authenticator will
  only release after it verifies you (fingerprint, face, or PIN). That value
  feeds a key-derivation function that unlocks your wallet locally. Nothing
  about the passkey is verified by a relying party, because there is no
  relying party.

Because a passkey carries full account control, Freewallet always requires user
verification (a biometric or PIN) for every passkey ceremony. A stolen,
already-unlocked device cannot silently unlock the wallet.

## Browser and platform support

Passkey unlock depends on the WebAuthn PRF extension, which is newer than
passkeys themselves. Some platforms create a perfectly good passkey but never
release a PRF value, and Freewallet cannot use those to unlock a wallet. There
is no reliable way to know in advance, so Freewallet always offers the passkey
option and, if PRF turns out to be unavailable, shows a clear message and lets
you fall back to your passphrase.

**Works today:**

- Recent Chrome and Edge (platform authenticators and hmac-secret security
  keys)
- Safari on macOS 15+ and iOS 18+
- Firefox 135+ (not on iOS)
- Android with Play Services 24.08.12 or newer
- Windows Hello

**Does not yield a PRF value (passphrase fallback needed):**

- NFC security keys on Android and iOS
- Linux platform authenticators
- iOS earlier than 18, and Firefox earlier than 135
- Security keys without CTAP2 hmac-secret
- macOS with USB security keys (inconsistent)

The passphrase option is always present, on every device and browser, so you
are never locked out because your platform cannot do PRF.

## Backup and recovery

Whether a lost device means a lost wallet depends on whether the passkey is
**synced** to your platform account (iCloud Keychain, Google Password Manager,
and similar). Freewallet reads two flags from each passkey when you create it
and shows the result as a badge in Settings:

- **Synced** -- the passkey is backed up to your platform account and available
  on your other signed-in devices. If a synced passkey exists on a new device,
  you can log in there with a single tap, even with the wallet's storage
  cleared.
- **Sync available** -- the passkey can be backed up but is not yet.
- **Not synced** -- the passkey lives only in this one authenticator. If you
  lose the device, this passkey is gone, and it cannot unlock your wallet from
  anywhere else.

**A not-synced passkey lost with its device cannot recover your wallet.** The
safest habit is to keep more than one way in: add a passphrase, or add a second
passkey on another device. Freewallet reminds you to do this after a
passkey-only signup, more urgently when your only passkey is not backed up.

Synced passkeys make recovery easy, but they move trust to your platform
account: whoever controls your iCloud or Google account can restore the passkey
and, with it, your wallet. That is the trade-off behind the convenience, and
worth choosing knowingly.

## Managing passkeys

From **Settings** you can:

- **Add a passkey** to an account that already has a passphrase, or add more
  passkeys to a passkey account.
- **Rename** a passkey so you can tell your devices apart.
- See each passkey's **sync badge**.
- **Remove** a passkey, including one on a device you no longer have. Removal
  genuinely retires the method -- the removed passkey can no longer unlock the
  wallet. Freewallet will not let you remove your last remaining unlock method,
  since that would leave the wallet unrecoverable.
- **Add a passphrase** to an account that was created with a passkey only, so
  you have a second way in.

## Learn More

- [Keys](#/docs/keys)
- [DIDs](#/docs/dids)
