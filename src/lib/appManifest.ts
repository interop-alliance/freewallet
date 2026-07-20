/**
 * Best-effort fetch of a requesting origin's Web App Manifest, for the App
 * Connect consent screen. The popup cannot read the app's HTML (cross-origin),
 * so it probes the two conventional manifest locations directly. Everything
 * here is display-only garnish over an attacker-controlled document: a missing
 * or unreadable manifest simply yields null, and callers must treat the
 * returned fields as untrusted free text / an untrusted image URL.
 */

const MANIFEST_PATHS = ['/manifest.webmanifest', '/manifest.json']

export interface AppManifestInfo {
  name?: string
  description?: string
  iconUrl?: string
}

interface ManifestIcon {
  src?: string
  sizes?: string
  purpose?: string
}

/**
 * Picks the largest usable icon from a manifest's `icons` array and resolves
 * its URL against the manifest URL. Monochrome-only icons (silhouette masks,
 * not logos) are skipped; only http(s) and data: URLs are accepted.
 *
 * @param options {object}
 * @param options.icons {ManifestIcon[]}
 * @param options.manifestUrl {string}
 * @returns {string | undefined}
 */
function pickIconUrl({
  icons,
  manifestUrl
}: {
  icons: ManifestIcon[]
  manifestUrl: string
}): string | undefined {
  let best: { url: string; size: number } | undefined
  for (const icon of icons) {
    if (typeof icon.src !== 'string' || icon.src === '') {
      continue
    }
    if (icon.purpose === 'monochrome') {
      continue
    }
    let url: URL
    try {
      url = new URL(icon.src, manifestUrl)
    } catch {
      continue
    }
    if (!['http:', 'https:', 'data:'].includes(url.protocol)) {
      continue
    }
    // "48x48 96x96" -> 96; "any" or missing -> 0 (kept only as a fallback).
    const size = (icon.sizes ?? '')
      .split(' ')
      .map(entry => Number.parseInt(entry, 10) || 0)
      .reduce((max, value) => Math.max(max, value), 0)
    if (!best || size > best.size) {
      best = { url: url.href, size }
    }
  }
  return best?.url
}

/**
 * Fetches the origin's Web App Manifest from its conventional locations
 * (`/manifest.webmanifest`, then `/manifest.json`). Requires the app server
 * to allow the request via CORS; any network, CORS, or parse failure returns
 * null rather than throwing.
 *
 * @param options {object}
 * @param options.origin {string}
 * @returns {Promise<AppManifestInfo | null>}
 */
export async function fetchAppManifest({
  origin
}: {
  origin: string
}): Promise<AppManifestInfo | null> {
  for (const path of MANIFEST_PATHS) {
    const manifestUrl = origin + path
    let manifest: Record<string, unknown>
    try {
      const response = await fetch(manifestUrl, {
        mode: 'cors',
        credentials: 'omit'
      })
      if (!response.ok) {
        continue
      }
      manifest = (await response.json()) as Record<string, unknown>
    } catch {
      continue
    }
    if (typeof manifest !== 'object' || manifest === null) {
      continue
    }
    const name =
      typeof manifest.name === 'string'
        ? manifest.name
        : typeof manifest.short_name === 'string'
          ? manifest.short_name
          : undefined
    const description =
      typeof manifest.description === 'string'
        ? manifest.description
        : undefined
    const iconUrl = Array.isArray(manifest.icons)
      ? pickIconUrl({ icons: manifest.icons as ManifestIcon[], manifestUrl })
      : undefined
    if (name === undefined && description === undefined && !iconUrl) {
      continue
    }
    return { name, description, iconUrl }
  }
  return null
}
