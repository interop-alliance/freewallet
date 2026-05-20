/** Reads verification log lines from a raw `verifyCredential` payload. */
export function getVerifyLogFromPayload(raw: Record<string, unknown>) {
  const results = raw.results as
    | Array<{ log?: Array<{ id: string }> }>
    | undefined
  const logFromFirstResult = results?.[0]?.log
  if (Array.isArray(logFromFirstResult)) {
    return logFromFirstResult
  }
  const topLevelLog = raw.log
  if (Array.isArray(topLevelLog)) {
    return topLevelLog
  }
  return []
}
