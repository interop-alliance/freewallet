/**
 * Lazy loader for the @zxcvbn-ts passphrase scoring engine, behind
 * `PasswordStrengthMeter`.
 *
 * The zxcvbn engine itself is tiny, but its frequency dictionaries are large,
 * so they are loaded on demand with dynamic import() the first time the meter
 * mounts. Vite code-splits the dictionaries into a separate chunk that stays
 * out of the initial bundle -- the meter only appears on the signup page, so
 * the cost is deferred until someone actually starts creating a wallet. The
 * matching Spanish dictionary is additionally loaded when the active locale is
 * Spanish, improving score accuracy for Spanish passphrases.
 *
 * Note: @zxcvbn-ts 4.x ships its dictionaries compressed and decompresses them
 * at load time via the transitive @zxcvbn-ts/dictionary-compression package,
 * whose CJS build has a broken default-export interop ("decompress is not a
 * function" when loaded through Node/CJS, including vitest under jsdom). This
 * does not affect the app, which is browser-only and resolves the working .mjs
 * build through Vite. The consequence: do NOT unit-test this module in a way
 * that triggers the real importer under vitest -- inject a stub importer, and
 * exercise the meter itself via the Playwright (browser) signup tests instead.
 */

export type Scorer = (password: string) => number

// Module-level cache so the dictionaries are configured only once per locale
// and shared across re-mounts of the component.
let cachedScorer: Scorer | null = null
let cachedSignature = ''
let pendingLoad: Promise<Scorer> | null = null

/**
 * The already-loaded scorer, if any. Lets the meter start from a scored first
 * render on re-mount instead of waiting for the loader promise again.
 *
 * @returns {Scorer | null}
 */
export function getCachedScorer(): Scorer | null {
  return cachedScorer
}

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
