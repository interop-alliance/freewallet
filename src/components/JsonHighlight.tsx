/**
 * Renders a JSON string as a syntax-highlighted, scrollable code block.
 *
 * Wraps prism-react-renderer's `Highlight` render-prop in an MUI `pre` box so
 * callers can drop in a highlighted source view without any imperative DOM
 * scanning (this replaces the old `microlight` + `reset()` approach). Token
 * colors come from the bundled dark Prism theme; the surrounding box styling
 * (background, padding, scroll behaviour) is supplied by the caller via `sx`.
 */

import Box from '@mui/material/Box'
import type { SxProps, Theme } from '@mui/material/styles'
import { Highlight, themes, type PrismTheme } from 'prism-react-renderer'

const jsonTheme: PrismTheme = themes.vsDark

export function JsonHighlight({
  code,
  sx
}: {
  code: string
  sx?: SxProps<Theme>
}) {
  return (
    <Highlight code={code} language="json" theme={jsonTheme}>
      {({ tokens, getLineProps, getTokenProps }) => (
        <Box component="pre" sx={sx}>
          {tokens.map((line, lineIndex) => (
            <div key={lineIndex} {...getLineProps({ line })}>
              {line.map((token, tokenIndex) => (
                <span key={tokenIndex} {...getTokenProps({ token })} />
              ))}
            </div>
          ))}
        </Box>
      )}
    </Highlight>
  )
}
