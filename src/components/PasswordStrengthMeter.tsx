/**
 * Password strength meter backed by @zxcvbn-ts.
 *
 * The engine and its (large, lazily imported) frequency dictionaries live
 * behind `loadScorer` in `@/lib/passwordScorer`; this file is only the
 * rendering layer. Do NOT unit-test this component under vitest -- mounting it
 * triggers the real dictionary import, which has a broken CJS interop under
 * jsdom (see the note in `passwordScorer.ts`). Exercise the meter via the
 * Playwright (browser) signup tests instead.
 */
import { useDeferredValue, useEffect, useMemo, useState } from 'react'
import { Box, Stack, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { getCachedScorer, loadScorer, type Scorer } from '@/lib/passwordScorer'
import { passwordStrengthStyles } from '@/styles/appStyles'

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
}: {
  password: string
  onChangeScore: (score: number) => void
  scoreWords: string[]
  shortScoreWord: string
}) {
  const { i18n } = useTranslation()
  // Lazy initializer: a bare `useState(cachedScorer)` would treat the cached
  // scorer function as an initializer and call it with no arguments (scoring
  // `undefined`), so wrap it to return the function itself as the state value.
  const [scorer, setScorer] = useState<Scorer | null>(() => getCachedScorer())
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

  // Scoring is a synchronous zxcvbn pass, heavy enough to be felt between
  // keystrokes, so it runs against a deferred copy of the passphrase: the field
  // stays responsive and the meter catches up a render later.
  const deferredPassword = useDeferredValue(password)

  // The score is a pure function of the passphrase and the loaded engine, so
  // it is derived during render rather than held in state.
  const score = useMemo(() => {
    if (!scorer || !deferredPassword) {
      return 0
    }
    return scorer(deferredPassword)
  }, [scorer, deferredPassword])

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
  const hasInput = deferredPassword.length > 0 && !loadFailed
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
