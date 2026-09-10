// @vitest-environment node
/**
 * The mender registry's audit (`src/session/menders/`): census completeness
 * over wallet-core's closed id list, the transient-reachable set read as a
 * pin, the derived gaps held inside the declared allowlist, every gap naming
 * a tracked item, and the code counterpart that holds each registered
 * converger's symbol to the source. The warn copy is the declarations' now
 * (the runner logs it), so what is checked here is that every chain
 * registration's invariants declare one, and that the four shared passes --
 * one registration each, so the runner's discipline covers them -- leave
 * that copy to the runner. The pins are read as pins rather than proofs:
 * re-pinning one takes a review note naming which entry moved and why.
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  deriveGaps,
  INVARIANT_IDS,
  transientReachableInvariants,
  undeclaredGaps,
  undeclaredInvariants,
  type InvariantId
} from '@interop/wallet-core/menders'
import {
  freewalletMenderRegistry,
  MENDER_GAPS,
  MENDER_INVARIANTS,
  MENDER_SITES,
  REMEMBERED_REGISTRATIONS,
  REMEMBERED_SEED,
  TRANSIENT_REGISTRATIONS
} from '../../src/session/menders/index.js'

/**
 * The design table's row number for an id, so the pins read as the design
 * reads.
 */
function rowOf(id: InvariantId): number {
  return INVARIANT_IDS.indexOf(id) + 1
}

function source(relative: string): string {
  return readFileSync(path.resolve(__dirname, '..', '..', relative), 'utf8')
}

describe('census completeness', () => {
  it('declares every invariant id exactly once, and every site and gap names a declared one', () => {
    expect(
      undeclaredInvariants({ registry: freewalletMenderRegistry })
    ).toEqual([])
    const declared = new Set(MENDER_INVARIANTS.map(decl => decl.id))
    for (const gap of MENDER_GAPS) {
      expect(declared.has(gap.invariant)).toBe(true)
    }
    expect(MENDER_INVARIANTS.map(decl => decl.id)).toEqual([...INVARIANT_IDS])
  })

  it('keeps the gap allowlist keyed by { invariant, tornState }', () => {
    const keys = MENDER_GAPS.map(gap => `${gap.invariant}\n${gap.tornState}`)
    expect(new Set(keys).size).toBe(keys.length)
  })

  it('registers no ceremony-tail site', () => {
    expect(MENDER_SITES.some(site => site.trigger === 'ceremony-tail')).toBe(
      false
    )
  })
})

describe('the transient-reachable set', () => {
  it('is the nineteen entries the design pins', () => {
    const reachable = transientReachableInvariants({
      registry: freewalletMenderRegistry
    })
    expect(reachable.map(rowOf)).toEqual([
      1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13, 14, 15, 16, 17, 18, 25, 26, 32
    ])
  })
})

describe('the gap allowlist', () => {
  it('derives the gaps the design lists, and every derived gap is declared', () => {
    const derived = deriveGaps({ registry: freewalletMenderRegistry })
    expect(
      derived
        .filter(gap => gap.kind === 'none')
        .map(gap => rowOf(gap.invariant))
    ).toEqual([2, 26, 28, 29, 30, 31, 32, 34])
    // Rows 11 and 27 moved out of `none` when stage B gave each an
    // addressable converger the pointer-heal registration reports. Rows 26
    // and 32 are the two detectors, `none` since a detector is not a mender.
    expect(
      derived
        .filter(gap => gap.kind === 'unreachable')
        .map(gap => rowOf(gap.invariant))
    ).toEqual([11, 19, 20, 22, 24, 27, 33])
    expect(undeclaredGaps({ derived, declared: MENDER_GAPS })).toEqual([])
  })

  it('names a tracked item on every row', () => {
    for (const gap of MENDER_GAPS) {
      expect(gap.item).toMatch(/^FW-\d+$/)
    }
  })

  it('declares no unreachable row whose invariant no site reports', () => {
    const reported = new Set(MENDER_SITES.flatMap(site => [...site.reports]))
    for (const gap of MENDER_GAPS) {
      if (gap.kind === 'unreachable') {
        expect(reported.has(gap.invariant)).toBe(true)
      }
    }
  })
})

describe('the code counterpart', () => {
  /**
   * The addressable convergers the site index registers, by the file that
   * exports them. A row moving out of this list is a registration the index
   * can no longer describe.
   */
  const exported: ReadonlyArray<{ row: number; file: string; symbol: string }> =
    [
      {
        row: 1,
        file: 'src/session/userKeySweep.ts',
        symbol: 'sweepUserKeyToDocument'
      },
      {
        row: 3,
        file: 'src/session/userKeyCascade.ts',
        symbol: 'cascadeCollectionsToUserKey'
      },
      {
        row: 4,
        file: 'src/session/registryReseal.ts',
        symbol: 'repairStaleUnlockRegistrySeal'
      },
      {
        row: 5,
        file: 'src/session/pendingRetirement.ts',
        symbol: 'repairTornPassphraseRetirement'
      },
      {
        row: 6,
        file: 'src/session/pendingRetirement.ts',
        symbol: 'rebuildBarePasskeyEntry'
      },
      {
        row: 7,
        file: 'src/session/unlockMethods.ts',
        symbol: 'backfillPassphraseUnlockMethod'
      },
      {
        row: 8,
        file: 'src/session/standingDelegationRefresh.ts',
        symbol: 'refreshStandingDelegations'
      },
      {
        row: 9,
        file: 'src/session/standingDelegationRefresh.ts',
        symbol: 'refreshCommittedLadderRung'
      },
      {
        row: 11,
        file: 'src/session/pointerHeal.ts',
        symbol: 'healAccountPointer'
      },
      {
        row: 15,
        file: 'src/session/transientLogin.ts',
        symbol: 'ensureClientAnnexGenerationReady'
      },
      {
        row: 16,
        file: 'src/session/annexReach.ts',
        symbol: 'ensureGenerationDelegation'
      },
      {
        row: 17,
        file: 'src/session/unlockMethods.ts',
        symbol: 'refreshTransientManageCapability'
      },
      {
        row: 18,
        file: 'src/session/annexReach.ts',
        symbol: 'refreshDidWebProjection'
      },
      {
        row: 19,
        file: 'src/session/clientAnnexGc.ts',
        symbol: 'sweepClientAnnexGenerations'
      },
      {
        row: 20,
        file: 'src/session/appKeySweep.ts',
        symbol: 'sweepStrandedAppKeys'
      },
      {
        row: 21,
        file: 'src/session/forget.ts',
        symbol: 'wipeStaleClientResidue'
      },
      {
        row: 22,
        file: 'src/session/forget.ts',
        symbol: 'assertClientStillEnrolled'
      },
      {
        row: 23,
        file: 'src/session/pendingEnrollment.ts',
        symbol: 'resumePendingEnrollment'
      },
      {
        row: 24,
        file: 'src/session/recovery.ts',
        symbol: 'resumeRecoverySpend'
      },
      {
        row: 27,
        file: 'src/stores/storageManager.ts',
        symbol: 'promoteAccountKeystore'
      }
    ]

  it('finds every registered converger exported from the file the table cites', () => {
    const reported = new Set(MENDER_SITES.flatMap(site => [...site.reports]))
    for (const { row, file, symbol } of exported) {
      const text = source(file)
      expect(text, `${symbol} in ${file}`).toMatch(
        new RegExp(`^export (async )?function ${symbol}\\b`, 'm')
      )
      expect(reported.has(INVARIANT_IDS[row - 1]!), `row ${row}`).toBe(true)
    }
    // The two facade methods: reachable through StorageManager rather than
    // as module exports.
    const facade = source('src/stores/storageManager.ts')
    expect(facade).toMatch(/^\s+(async )?ensureUserCollections\(/m)
    expect(facade).toMatch(/^\s+async ensurePromotedController\(/m)
    // The credential-anchored mend, one call running every arm.
    const mend = source('src/session/transientLogin.ts')
    expect(mend).toMatch(/mendCredentialAnchoredAccount\(/)
  })

  it('declares a warn string for every invariant a chain registration reports', () => {
    for (const registration of [
      REMEMBERED_SEED,
      ...REMEMBERED_REGISTRATIONS,
      ...TRANSIENT_REGISTRATIONS
    ]) {
      for (const id of registration.reports) {
        const decl = freewalletMenderRegistry.byId(id)
        expect(decl?.warn, id).toBeTruthy()
      }
    }
  })

  it("leaves the four shared passes' warn copy to the runner alone", () => {
    // Each of the four is its own registration, so the runner's one try,
    // warn, and skip discipline covers it: a throwing re-seal warns with its
    // declared string and the block carries on to the backfill. The passes
    // must not repeat that copy, or a login logs each failure twice.
    const passes = source('src/session/registryPasses.ts')
    for (const row of [4, 5, 6, 7]) {
      const decl = freewalletMenderRegistry.byId(INVARIANT_IDS[row - 1]!)!
      expect(passes, `row ${row}`).not.toContain(decl.warn)
    }
  })

  it('registers each shared pass on its own, so one failure skips no other', () => {
    const shared = new Set<InvariantId>([
      'unlock-registry-opens-under-the-current-user-key',
      'registry-passphrase-entry-names-the-standing-credential',
      'passkey-entry-carries-its-standing-configuration',
      'registry-lists-the-passphrase-method'
    ])
    for (const list of [REMEMBERED_REGISTRATIONS, TRANSIENT_REGISTRATIONS]) {
      for (const registration of list) {
        const reported = registration.reports.filter(id => shared.has(id))
        if (reported.length > 0) {
          expect(registration.reports).toHaveLength(1)
        }
      }
    }
  })
})
