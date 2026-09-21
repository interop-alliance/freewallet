/**
 * Saving a byte stream to a file the user picks, the one path the archive
 * downloads take.
 *
 * The save is two steps, because where the file goes is asked before the
 * bytes exist. With the File System Access API, {@link pickSaveFile} opens the
 * picker and answers a target whose `write` pipes a stream into the chosen
 * file; a caller that runs a long ceremony first therefore asks the question
 * before it starts, so a dismissed picker costs nothing. Without the API
 * (Firefox and Safari) `pickSaveFile` answers `undefined` and the caller
 * hands the finished stream to {@link saveStreamAsBlob}, which buffers it and
 * takes the ordinary anchor download.
 *
 * A picker the user dismisses throws `AbortError`, which is left to the
 * caller: cancelling a save is not a failure.
 */
import { downloadBlob } from '@/lib/downloadBlob'

/**
 * Asks the user where to save a tar archive, before the bytes exist.
 *
 * @param options {object}
 * @param options.fileName {string}   the suggested file name
 * @returns {Promise<object | undefined>}   the chosen file, waiting for its
 *   bytes, or `undefined` where the browser has no picker
 */
export async function pickSaveFile({
  fileName
}: {
  fileName: string
}): Promise<
  { write: (stream: ReadableStream<Uint8Array>) => Promise<void> } | undefined
> {
  // The File System Access API's save picker, typed to the members used
  // here.
  const windowWithPicker = window as Window & {
    showSaveFilePicker?: (options?: {
      suggestedName?: string
      types?: Array<{
        description?: string
        accept?: Record<string, string[]>
      }>
    }) => Promise<{ createWritable: () => Promise<WritableStream> }>
  }
  if (typeof windowWithPicker.showSaveFilePicker !== 'function') {
    return undefined
  }
  const fileHandle = await windowWithPicker.showSaveFilePicker({
    suggestedName: fileName,
    types: [
      { description: 'TAR archive', accept: { 'application/x-tar': ['.tar'] } }
    ]
  })
  return {
    write: async (stream: ReadableStream<Uint8Array>): Promise<void> => {
      const writable = await fileHandle.createWritable()
      await stream.pipeTo(writable)
    }
  }
}

/**
 * Buffers a stream into a Blob and downloads it, the path a browser with no
 * save picker takes.
 *
 * @param options {object}
 * @param options.stream {ReadableStream<Uint8Array>}   the bytes to save
 * @param options.fileName {string}   the file name the download carries
 * @returns {Promise<void>}
 */
export async function saveStreamAsBlob({
  stream,
  fileName
}: {
  stream: ReadableStream<Uint8Array>
  fileName: string
}): Promise<void> {
  const blob = await new Response(stream).blob()
  downloadBlob({ blob, filename: fileName })
}
