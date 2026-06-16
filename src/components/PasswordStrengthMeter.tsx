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
 * Lazily loads and configures the zxcvbn engine for the given locale, then
 * returns a function that scores a passphrase (0-4). Repeat calls for the same
 * locale reuse the cached scorer instead of re-importing the dictionaries.
 *
 * @param options {object}
 * @param options.language {string}   active i18n language code (e.g. 'en', 'es')
 * @returns {Promise<Scorer>}
 */
async function loadScorer({ language }: { language: string }): Promise<Scorer> {
  const useSpanish = language.startsWith('es')
  const signature = useSpanish ? 'es' : 'en'
  if (cachedScorer && cachedSignature === signature) {
    return cachedScorer
  }
  if (pendingLoad && cachedSignature === signature) {
    return pendingLoad
  }
  cachedSignature = signature
  pendingLoad = (async function configure() {
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
    cachedScorer = (password: string) => zxcvbn.check(password).score
    return cachedScorer
  })()
  return pendingLoad
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

  useEffect(() => {
    let cancelled = false
    void loadScorer({ language: i18n.language }).then(fn => {
      if (!cancelled) {
        setScorer(() => fn)
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
  // component's point of view) whenever it changes.
  useEffect(() => {
    onChangeScore(score)
  }, [score, onChangeScore])

  const hasInput = password.length > 0
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
