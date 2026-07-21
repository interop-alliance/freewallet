import type { SxProps, Theme } from '@mui/material/styles'
import { credentialDetailCardStyles } from '@/styles/credentialStyles'

const markdownBase = credentialDetailCardStyles.markdownBody

/**
 * The resume preview is a deliberate print-style, light-only surface: it fixes
 * its own typeface and link color rather than following the app theme. The font
 * family is set once on the root `page` container and inherited by every
 * descendant (see the `& *` rule below); the link color is named here so it is
 * defined in a single place.
 */
const RESUME_FONT = 'Arial, sans-serif'
const RESUME_LINK_COLOR = '#007bff'

export type ResumeStylesMap = {
  page: SxProps<Theme>
  header: SxProps<Theme>
  headerInner: SxProps<Theme>
  headerNameRow: SxProps<Theme>
  fullName: SxProps<Theme>
  city: SxProps<Theme>
  contactRow: SxProps<Theme>
  contactLink: SxProps<Theme>
  contactSeparator: SxProps<Theme>
  body: SxProps<Theme>
  sectionBlock: SxProps<Theme>
  sectionTitle: SxProps<Theme>
  summaryMarkdown: SxProps<Theme>
  itemBlock: SxProps<Theme>
  experienceTitle: SxProps<Theme>
  experienceMeta: SxProps<Theme>
  experienceDuration: SxProps<Theme>
  experienceMarkdown: SxProps<Theme>
  educationTitle: SxProps<Theme>
  educationDates: SxProps<Theme>
  educationMarkdown: SxProps<Theme>
  skillsList: SxProps<Theme>
  skillItem: SxProps<Theme>
  affiliationsSection: SxProps<Theme>
  affiliationTitle: SxProps<Theme>
  affiliationDuration: SxProps<Theme>
}

export const resumeStyles: ResumeStylesMap = {
  page: {
    width: '100%',
    mx: 'auto',
    bgcolor: '#fff',
    border: 1,
    borderColor: 'divider',
    borderRadius: 2,
    overflow: 'hidden',
    position: 'relative' as const,
    display: 'flex',
    flexDirection: 'column' as const,
    fontFamily: RESUME_FONT,
    // Force every descendant onto the resume typeface, overriding the font
    // family each MUI Typography variant would otherwise apply.
    '& *': { fontFamily: 'inherit' }
  },
  header: {
    backgroundColor: '#F5F5F5',
    py: 2.5,
    pl: { xs: 2, sm: '36px' },
    pr: { xs: 2, sm: '36px' }
  },
  headerInner: {
    display: 'flex',
    flexDirection: 'column' as const,
    justifyContent: 'center',
    gap: 0.5,
    minWidth: 0
  },
  headerNameRow: {
    display: 'flex',
    flexWrap: 'wrap',
    alignItems: 'baseline',
    gap: 2
  },
  fullName: {
    fontWeight: 600,
    color: '#000',
    fontSize: { xs: '1.5rem', sm: '1.75rem' },
    lineHeight: 1
  },
  city: {
    fontWeight: 400,
    color: '#666',
    fontSize: '1.05rem'
  },
  contactRow: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: 1.5,
    alignItems: 'center'
  },
  contactLink: {
    color: RESUME_LINK_COLOR,
    fontSize: '15px',
    fontWeight: 400
  },
  contactSeparator: {
    color: '#666',
    fontSize: '15px'
  },
  body: {
    flex: 1,
    px: { xs: 2, sm: '36px' },
    py: '24px',
    pb: '20px'
  },
  sectionBlock: {
    mb: '14px'
  },
  sectionTitle: {
    fontWeight: 700,
    mb: '8px',
    pb: '4px',
    fontSize: '16px',
    lineHeight: 1.2,
    color: '#111',
    borderBottom: '1.5px solid',
    borderColor: 'divider'
  },
  summaryMarkdown: {
    ...markdownBase,
    color: '#000',
    fontSize: '14px',
    lineHeight: 1.4
  },
  itemBlock: {
    mb: '12px'
  },
  experienceTitle: {
    fontWeight: 700,
    fontSize: '16px'
  },
  experienceMeta: {
    fontSize: '14px',
    color: '#000'
  },
  experienceDuration: {
    fontSize: '14px',
    color: '#000',
    mb: 0.5
  },
  experienceMarkdown: {
    ...markdownBase,
    fontSize: '14px',
    lineHeight: 1.4
  },
  educationTitle: {
    fontWeight: 700,
    fontSize: '15px'
  },
  educationDates: {
    fontSize: '15px'
  },
  educationMarkdown: {
    ...markdownBase,
    mt: 0.5
  },
  skillsList: {
    pl: 2.5,
    m: 0
  },
  skillItem: {
    fontWeight: 400,
    fontSize: '16px',
    mb: 1,
    display: 'list-item' as const
  },
  affiliationsSection: {
    mb: 0
  },
  affiliationTitle: {
    fontWeight: 700,
    fontSize: '16px'
  },
  affiliationDuration: {
    fontSize: '16px',
    fontWeight: 400,
    color: '#000'
  }
}
