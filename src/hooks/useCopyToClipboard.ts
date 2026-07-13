import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * React hook wrapping the copy-to-clipboard ritual shared across the app.
 *
 * Returns a `copied` flag that flips true right after a successful copy and
 * resets to false after `resetDelay` milliseconds (call sites drive their
 * "Copied" tooltip/label off it), a `copy(text)` action, and a `reset()`
 * that clears the flag and any pending reset timer immediately. The reset
 * timer is always cleared on unmount.
 *
 * When `fallbackToExecCommand` is set and the async Clipboard API rejects (for
 * example in a non-secure context, where `navigator.clipboard` is
 * unavailable), the copy falls back to the deprecated
 * `document.execCommand('copy')` off a hidden textarea. It is opt-in so call
 * sites that never had the fallback keep their exact behaviour. `onError` is
 * invoked only once the copy has genuinely failed -- not when the async path
 * fails but the fallback then succeeds.
 *
 * @param options {object}
 * @param [options.resetDelay] {number} - Milliseconds before `copied` resets.
 * @param [options.fallbackToExecCommand] {boolean} - Enable the execCommand
 *   fallback for non-secure contexts.
 * @param [options.onError] {(err: unknown) => void} - Called when the copy
 *   ultimately fails.
 * @returns {{ copied: boolean, copy: (text: string) => Promise<boolean>,
 *   reset: () => void }}
 */
export function useCopyToClipboard({
  resetDelay = 1500,
  fallbackToExecCommand = false,
  onError
}: {
  resetDelay?: number
  fallbackToExecCommand?: boolean
  onError?: (err: unknown) => void
} = {}) {
  const [copied, setCopied] = useState(false)
  const resetTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const clearResetTimer = useCallback(() => {
    if (resetTimerRef.current) {
      clearTimeout(resetTimerRef.current)
      resetTimerRef.current = null
    }
  }, [])

  useEffect(() => {
    return () => {
      clearResetTimer()
    }
  }, [clearResetTimer])

  const reset = useCallback(() => {
    setCopied(false)
    clearResetTimer()
  }, [clearResetTimer])

  const markCopied = useCallback(() => {
    setCopied(true)
    clearResetTimer()
    resetTimerRef.current = setTimeout(() => {
      setCopied(false)
      resetTimerRef.current = null
    }, resetDelay)
  }, [clearResetTimer, resetDelay])

  const copy = useCallback(
    async (text: string): Promise<boolean> => {
      try {
        await navigator.clipboard.writeText(text)
        markCopied()
        return true
      } catch (err) {
        // Without a fallback the copy has failed -- report and bail.
        if (!fallbackToExecCommand) {
          onError?.(err)
          return false
        }
        // Otherwise fall through to the execCommand path below.
      }
      try {
        const textArea = document.createElement('textarea')
        textArea.value = text
        textArea.setAttribute('readonly', '')
        textArea.style.position = 'fixed'
        textArea.style.left = '-9999px'
        document.body.appendChild(textArea)
        textArea.select()
        document.execCommand('copy')
        document.body.removeChild(textArea)
        markCopied()
        return true
      } catch (err) {
        onError?.(err)
        return false
      }
    },
    [fallbackToExecCommand, markCopied, onError]
  )

  return { copied, copy, reset }
}
