/**
 * Requester-supplied free text on a consent screen: an attribution label
 * ("The site says:") over the text itself, italicized and line-clamped.
 * Everything rendered here is attacker-controlled, so the guards are the
 * point: a non-string wire value renders nothing (an object as a React child
 * would crash the popup), and the text is truncated TEXTUALLY, not only
 * visually -- a CSS line clamp leaves the full text in the DOM and the
 * accessibility tree, where a screen reader would read an arbitrarily long
 * requester message ahead of the trusted consent rows.
 */
import Typography from '@mui/material/Typography'

const MAX_TEXT_CHARS = 280

export function SiteProvidedText({
  text,
  label
}: {
  // The site-supplied value, straight off the wire -- deliberately unknown.
  text: unknown
  // The already-translated attribution label rendered above the text.
  label: string
}) {
  if (typeof text !== 'string' || text === '') {
    return null
  }
  const truncated =
    text.length > MAX_TEXT_CHARS ? text.slice(0, MAX_TEXT_CHARS) + '...' : text
  return (
    <>
      <Typography
        variant="caption"
        color="text.secondary"
        sx={{ display: 'block' }}
      >
        {label}
      </Typography>
      {/* Clamped as well: even the truncated text must not push the trusted
          rows below it out of view. */}
      <Typography
        variant="body2"
        sx={{
          mb: 0.5,
          fontStyle: 'italic',
          display: '-webkit-box',
          WebkitLineClamp: 3,
          WebkitBoxOrient: 'vertical',
          overflow: 'hidden',
          overflowWrap: 'anywhere'
        }}
      >
        {truncated}
      </Typography>
    </>
  )
}
