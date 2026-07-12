/**
 * Password strength meter backed by @zxcvbn-ts.
 *
 * The zxcvbn engine itself is tiny, but its frequency dictionaries are large,
 * so they are loaded on demand with dynamic import() the first time this
 * component mounts. Vite code-splits the dictionaries into a separate chunk
 * that stays out of the initial bundle -- the meter only appears on the signup
 * page, so the cost is deferred until someone actually starts creating a
 * wallet. The matching Spanish dictionary is additionally loaded when the
 * active locale is Spanish, improving score accuracy for Spanish passphrases.
 *
 * Note: @zxcvbn-ts 4.x ships its dictionaries compressed and decompresses them
 * at load time via the transitive @zxcvbn-ts/dictionary-compression package,
 * whose CJS build has a broken default-export interop ("decompress is not a
 * function" when loaded through Node/CJS, including vitest under jsdom). This
 * does not affect the app, which is browser-only and resolves the working .mjs
 * build through Vite. The consequence: do NOT unit-test this component in a way
 * that triggers loadScorer() under vitest -- exercise the meter via the
 * Playwright (browser) signup tests instead.
 */
import { useEffect, useMemo, useState } from 'react'
import { Box, Stack, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { passwordStrengthStyles } from '@/styles/appStyles'

type Scorer = (password: string) => number

const SEGMENT_COUNT = 5

/**
 * Highest score the zxcvbn engine can report (scores run 0-4). Reported to the
 * parent as a passing score when the engine fails to load, so a flaky
 * dictionary chunk fetch degrades to length-only gating instead of a permanent
 * block on signup / passphrase change.
 */
const MAX_SCORE = SEGMENT_COUNT - 1

/**
 * zxcvbn score (0-4) mapped to an MUI palette colour token. Indexed by score,
 * so weak passphrases read red and strong ones green.
 */
const SCORE_COLORS = [
  'error.main',
  'error.main',
  'warning.main',
  'info.main',
  'success.main'
] as const

// Module-level cache so the dictionaries are configured only once per locale
// and shared across re-mounts of the component.
let cachedScorer: Scorer | null = null
let cachedSignature = ''
let pendingLoad: Promise<Scorer> | null = null

/**
 * Dynamically imports the zxcvbn engine and its dictionaries and builds a
 * scorer. Extracted from loadScorer so that the caching layer can be exercised
 * in isolation (tests inject a stub importer, avoiding the real dictionary
 * chunks -- see the CJS interop note in the file header).
 *
 * @param options {object}
 * @param options.useSpanish {boolean}   also load the Spanish dictionary
 * @returns {Promise<Scorer>}
 */
async function importZxcvbnScorer({
  useSpanish
}: {
  useSpanish: boolean
}): Promise<Scorer> {
  const [core, common, en, es] = await Promise.all([
    import('@zxcvbn-ts/core'),
    import('@zxcvbn-ts/language-common'),
    import('@zxcvbn-ts/language-en'),
    useSpanish ? import('@zxcvbn-ts/language-es-es') : Promise.resolve(null)
  ])
  const { ZxcvbnFactory } = core
  const zxcvbn = new ZxcvbnFactory({
    dictionary: {
      ...common.dictionary,
      ...en.dictionary,
      ...(es ? es.dictionary : {})
    },
    graphs: common.adjacencyGraphs,
    translations: en.translations
  })
  return (password: string) => zxcvbn.check(password).score
}

/**
 * Lazily loads and configures the zxcvbn engine for the given locale, then
 * returns a function that scores a passphrase (0-4). Repeat calls for the same
 * locale reuse the cached scorer instead of re-importing the dictionaries.
 *
 * A rejected load (a flaky dictionary chunk fetch) clears the module-level
 * cache so a later call retries the import from scratch, rather than every
 * subsequent caller receiving the same poisoned, permanently-rejected promise.
 *
 * @param options {object}
 * @param options.language {string}   active i18n language code (e.g. 'en', 'es')
 * @param [options.importScorer {function}]   injectable importer (tests only)
 * @returns {Promise<Scorer>}
 */
export async function loadScorer({
  language,
  importScorer = importZxcvbnScorer
}: {
  language: string
  importScorer?: (options: { useSpanish: boolean }) => Promise<Scorer>
}): Promise<Scorer> {
  const useSpanish = language.startsWith('es')
  const signature = useSpanish ? 'es' : 'en'
  if (cachedScorer && cachedSignature === signature) {
    return cachedScorer
  }
  if (pendingLoad && cachedSignature === signature) {
    return pendingLoad
  }
  cachedSignature = signature
  const thisLoad = (async function configure() {
    cachedScorer = await importScorer({ useSpanish })
    return cachedScorer
  })()
  // Evict a rejected load from the cache so the next caller retries instead of
  // reusing the poisoned promise. Guarded on identity so an in-flight retry is
  // not clobbered by a stale rejection.
  thisLoad.catch(() => {
    if (pendingLoad === thisLoad) {
      pendingLoad = null
      cachedSignature = ''
    }
  })
  pendingLoad = thisLoad
  return thisLoad
}

/**
 * Resets the module-level scorer cache. Test-only hook so each case starts from
 * a clean loader state.
 */
export function __resetScorerCacheForTests(): void {
  cachedScorer = null
  cachedSignature = ''
  pendingLoad = null
}

interface PasswordStrengthMeterProps {
  password: string
  onChangeScore: (score: number) => void
  scoreWords: string[]
  shortScoreWord: string
}

/**
 * Renders a segmented strength bar plus a textual label for a passphrase.
 *
 * @param options {object}
 * @param options.password {string}              passphrase being evaluated
 * @param options.onChangeScore {function}       called with the latest score (0-4)
 * @param options.scoreWords {string[]}          labels keyed by score index
 * @param options.shortScoreWord {string}        label shown when the field is empty
 * @returns {JSX.Element}
 */
export function PasswordStrengthMeter({
  password,
  onChangeScore,
  scoreWords,
  shortScoreWord
}: PasswordStrengthMeterProps) {
  const { i18n } = useTranslation()
  // Lazy initializer: a bare `useState(cachedScorer)` would treat the cached
  // scorer function as an initializer and call it with no arguments (scoring
  // `undefined`), so wrap it to return the function itself as the state value.
  const [scorer, setScorer] = useState<Scorer | null>(() => cachedScorer)
  // Set when the engine fails to load. The meter cannot measure strength, so it
  // degrades to an inert bar and reports a passing score -- gating submission on
  // length alone rather than blocking it until a full page reload.
  const [loadFailed, setLoadFailed] = useState(false)

  useEffect(() => {
    let cancelled = false
    loadScorer({ language: i18n.language })
      .then(fn => {
        if (!cancelled) {
          setLoadFailed(false)
          setScorer(() => fn)
        }
      })
      .catch(() => {
        if (!cancelled) {
          setLoadFailed(true)
        }
      })
    return () => {
      cancelled = true
    }
  }, [i18n.language])

  // The score is a pure function of the passphrase and the loaded engine, so
  // it is derived during render rather than held in state.
  const score = useMemo(() => {
    if (!scorer || !password) {
      return 0
    }
    return scorer(password)
  }, [scorer, password])

  // Report the latest score to the parent (an external system from this
  // component's point of view) whenever it changes. When the engine failed to
  // load, report a passing score so a flaky chunk fetch never permanently
  // disables the parent's submit gate.
  const reportedScore = loadFailed ? MAX_SCORE : score
  useEffect(() => {
    onChangeScore(reportedScore)
  }, [reportedScore, onChangeScore])

  // A failed engine renders as an inert meter (no fill, neutral label): the
  // component cannot honestly grade strength, so it shows nothing rather than a
  // misleading colour.
  const hasInput = password.length > 0 && !loadFailed
  const activeColor = hasInput ? SCORE_COLORS[score] : 'text.secondary'
  const label = hasInput ? (scoreWords[score] ?? '') : shortScoreWord

  return (
    <Box sx={passwordStrengthStyles.wrap}>
      <Stack direction="row" sx={passwordStrengthStyles.segments}>
        {Array.from({ length: SEGMENT_COUNT }, (_unused, index) => {
          const filled = hasInput && index <= score
          return (
            <Box
              key={index}
              sx={{
                ...passwordStrengthStyles.segment,
                bgcolor: filled
                  ? SCORE_COLORS[score]
                  : 'action.disabledBackground'
              }}
            />
          )
        })}
      </Stack>
      <Typography
        variant="body2"
        sx={{ ...passwordStrengthStyles.label, color: activeColor }}
      >
        {label}
      </Typography>
    </Box>
  )
}
