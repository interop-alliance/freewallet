export const landingStyles = {
  main: {
    minHeight: '100dvh',
    display: 'flex',
    flexDirection: 'column'
  },
  /**
   * Hero frame below the app bar: top-aligned, horizontally centered. The
   * West Coast theme's own `.fw-frame` padding overrides these paddings.
   */
  frame: {
    width: '100%',
    px: 2,
    pt: { xs: 6, sm: 10 },
    pb: 6
  },
  content: {
    textAlign: 'center',
    maxWidth: 760,
    width: '100%'
  },
  /** West Coast hero card inner inset — padding on a child so it isn't clipped/overridden. */
  westCoastHeroCardInner: {
    boxSizing: 'border-box',
    width: '100%',
    px: { xs: 3.5, sm: 7 },
    pt: { xs: 5, sm: 8 },
    pb: { xs: 6, sm: 10 }
  },
  westCoastHeroFrame: {
    maxWidth: { xs: '100%', sm: 960 }
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
    mx: 'auto',
    width: '100%',
    fontSize: { xs: '1rem', sm: '1.0625rem' },
    whiteSpace: { xs: 'normal', sm: 'nowrap' }
  },
  link: {
    color: 'inherit'
  },
  actions: {
    flexDirection: { xs: 'column', sm: 'row' },
    flexWrap: 'wrap',
    justifyContent: 'center',
    alignItems: 'stretch',
    gap: 2
  },
  button: {
    minWidth: 180,
    py: 1.25
  },
  /**
   * Build-config warning shown below the hero card (e.g. missing WAS server).
   */
  configWarning: {
    color: 'error.main',
    mt: 3,
    width: '100%',
    textAlign: 'center'
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
