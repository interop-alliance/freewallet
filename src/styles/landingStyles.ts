export const landingStyles = {
  main: {
    minHeight: '100dvh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    px: 2,
  },
  /**
   * Sits at the top of the hero column, above headings (aligned end = right in LTR).
   */
  languageBar: {
    display: 'flex',
    justifyContent: 'flex-end',
    width: '100%',
    mb: 2,
  },
  content: {
    textAlign: 'center',
    maxWidth: 760,
    width: '100%'
  },
  title: {
    fontWeight: 500,
    mb: 2,
    fontSize: { xs: '2.2rem', sm: '3rem' }
  },
  subtitle: {
    color: 'text.secondary',
    fontWeight: 400,
    lineHeight: 1.45,
    mb: 6,
    maxWidth: 620,
    mx: 'auto',
    fontSize: { xs: '1.125rem', sm: '1.45rem' }
  },
  link: {
    color: 'inherit'
  },
  actions: {
    flexDirection: { xs: 'column', sm: 'row' },
    justifyContent: 'center',
    alignItems: 'stretch',
    gap: 2
  },
  button: {
    minWidth: 180,
    py: 1.25
  },
  /**
   * Guest Mode CTA: base button sizing + guest emphasis
   */
  guestModeButton: {
    minWidth: 230,
    py: 1.25,
    textTransform: 'uppercase',
    letterSpacing: 0.8
  }
} as const
