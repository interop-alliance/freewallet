/**
 * Requester-supplied free text on a consent screen: an attribution label
 * ("The site says:") inline ahead of the text itself, which is italicized
 * and line-clamped. The label shares the text's first line, so a grant card
 * carrying a reason stays short.
 * Everything rendered here is attacker-controlled, so the guards are the
 * point: a non-string wire value renders nothing (an object as a React child
 * would crash the popup), and the text is truncated TEXTUALLY, not only
 * visually -- a CSS line clamp leaves the full text in the DOM and the
 * accessibility tree, where a screen reader would read an arbitrarily long
 * requester message ahead of the trusted consent rows.
 */
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'

const MAX_TEXT_CHARS = 280

export function SiteProvidedText({
  text,
  label
}: {
  // The site-supplied value, straight off the wire -- deliberately unknown.
  text: unknown
  // The already-translated attribution label rendered ahead of the text.
  label: string
}) {
  if (typeof text !== 'string' || text === '') {
    return null
  }
  const truncated =
    text.length > MAX_TEXT_CHARS ? text.slice(0, MAX_TEXT_CHARS) + '...' : text
  return (
    <Typography
      variant="body2"
      sx={{
        mb: 0.5,
        // Clamped as well: even the truncated text must not push the trusted
        // rows below it out of view.
        display: '-webkit-box',
        WebkitLineClamp: 3,
        WebkitBoxOrient: 'vertical',
        overflow: 'hidden',
        overflowWrap: 'anywhere'
      }}
    >
      <Typography
        component="span"
        variant="caption"
        color="text.secondary"
        sx={{ mr: 0.5 }}
      >
        {label}
      </Typography>
      <Box component="span" sx={{ fontStyle: 'italic' }}>
        {truncated}
      </Box>
    </Typography>
  )
}
