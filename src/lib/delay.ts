/**
 * Resolves after the given number of milliseconds -- a promise wrapper around
 * setTimeout, for awaiting a pause in async code.
 *
 * @param milliseconds {number}   how long to wait before resolving
 * @returns {Promise<void>}
 */
export async function delay(milliseconds: number): Promise<void> {
  return new Promise<void>(resolve => setTimeout(resolve, milliseconds))
}
