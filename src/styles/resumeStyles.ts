import type { SxProps, Theme } from '@mui/material/styles'
import { credentialDetailCardStyles } from '@/styles/credentialStyles'

const markdownBase = credentialDetailCardStyles.markdownBody

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
    maxWidth: '210mm',
    minHeight: '297mm',
    mx: 'auto',
    bgcolor: '#fff',
    border: '1px solid #78809A',
    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
    position: 'relative' as const,
    display: 'flex',
    flexDirection: 'column' as const
  },
  header: {
    backgroundColor: '#F5F5F5',
    py: 2,
    pl: { xs: 2, sm: '45px' },
    pr: { xs: 2, sm: '45px' }
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
    lineHeight: 1,
    fontFamily: 'Arial, sans-serif'
  },
  city: {
    fontWeight: 400,
    color: '#666',
    fontSize: '1.05rem',
    fontFamily: 'Arial, sans-serif'
  },
  contactRow: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: 1.5,
    alignItems: 'center'
  },
  contactLink: {
    color: '#007bff',
    fontSize: '15px',
    fontWeight: 400,
    fontFamily: 'Arial, sans-serif'
  },
  contactSeparator: {
    color: '#666',
    fontSize: '15px'
  },
  body: {
    flex: 1,
    px: { xs: 2, sm: '50px' },
    py: '20px',
    pb: '15px'
  },
  sectionBlock: {
    mb: '14px'
  },
  sectionTitle: {
    fontWeight: 700,
    mb: '10px',
    fontSize: '17px',
    lineHeight: 1.2,
    color: '#000',
    fontFamily: 'Arial, sans-serif'
  },
  summaryMarkdown: {
    ...markdownBase,
    color: '#000',
    fontSize: '14px',
    fontFamily: 'Arial, sans-serif',
    lineHeight: 1.4
  },
  itemBlock: {
    mb: '12px'
  },
  experienceTitle: {
    fontWeight: 700,
    fontSize: '16px',
    fontFamily: 'Arial, sans-serif'
  },
  experienceMeta: {
    fontSize: '14px',
    fontFamily: 'Arial, sans-serif',
    color: '#000'
  },
  experienceDuration: {
    fontSize: '14px',
    fontFamily: 'Arial, sans-serif',
    color: '#000',
    mb: 0.5
  },
  experienceMarkdown: {
    ...markdownBase,
    fontSize: '14px',
    fontFamily: 'Arial, sans-serif',
    lineHeight: 1.4
  },
  educationTitle: {
    fontWeight: 700,
    fontSize: '15px',
    fontFamily: 'Arial, sans-serif'
  },
  educationDates: {
    fontFamily: 'Arial, sans-serif',
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
    fontFamily: 'Arial, sans-serif',
    mb: 1,
    display: 'list-item' as const
  },
  affiliationsSection: {
    mb: 0
  },
  affiliationTitle: {
    fontWeight: 700,
    fontSize: '16px',
    fontFamily: 'Arial, sans-serif'
  },
  affiliationDuration: {
    fontSize: '16px',
    fontFamily: 'Arial, sans-serif',
    fontWeight: 400,
    color: '#000'
  }
}
