import type { ReactNode } from 'react'
import Box from '@mui/material/Box'
import Link from '@mui/material/Link'
import Typography from '@mui/material/Typography'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import type { ResumePreviewModel } from '@/types/resume'
import { resumeStyles as rpStyles } from '@/styles/resumeStyles'

function SectionTitle({ children }: { children: ReactNode }) {
  return (
    <Typography component="h3" sx={rpStyles.sectionTitle}>
      {children}
    </Typography>
  )
}

export function ResumePreview({ data }: { data: ResumePreviewModel }) {
  const {
    fullName,
    city,
    email,
    phone,
    summary,
    experience,
    education,
    skills,
    affiliations
  } = data

  return (
    <Box sx={rpStyles.page}>
      <Box sx={rpStyles.header}>
        <Box sx={rpStyles.headerInner}>
          <Box sx={rpStyles.headerNameRow}>
            <Typography sx={rpStyles.fullName}>{fullName}</Typography>
            {city && <Typography sx={rpStyles.city}>{city}</Typography>}
          </Box>

          {(email || phone) && (
            <Box sx={rpStyles.contactRow}>
              {email && (
                <Link
                  href={`mailto:${email}`}
                  underline="hover"
                  sx={rpStyles.contactLink}
                >
                  {email}
                </Link>
              )}
              {email && phone && (
                <Typography sx={rpStyles.contactSeparator}>|</Typography>
              )}
              {phone && (
                <Link
                  href={`tel:${phone}`}
                  underline="hover"
                  sx={rpStyles.contactLink}
                >
                  {phone}
                </Link>
              )}
            </Box>
          )}
        </Box>
      </Box>

      <Box sx={rpStyles.body}>
        {summary ? (
          <Box sx={rpStyles.sectionBlock}>
            <SectionTitle>Professional Summary</SectionTitle>
            <Box sx={rpStyles.summaryMarkdown}>
              <ReactMarkdown remarkPlugins={[remarkGfm]}>
                {summary}
              </ReactMarkdown>
            </Box>
          </Box>
        ) : null}

        {experience.length > 0 && (
          <Box sx={rpStyles.sectionBlock}>
            <SectionTitle>Work Experience</SectionTitle>
            {experience.map(row => (
              <Box key={row.id} sx={rpStyles.itemBlock}>
                <Typography sx={rpStyles.experienceTitle}>
                  {row.title}
                </Typography>
                {row.company && (
                  <Typography sx={rpStyles.experienceMeta}>
                    {row.company}
                  </Typography>
                )}
                {row.duration && (
                  <Typography sx={rpStyles.experienceDuration}>
                    {row.duration}
                  </Typography>
                )}
                {row.description && (
                  <Box sx={rpStyles.experienceMarkdown}>
                    <ReactMarkdown remarkPlugins={[remarkGfm]}>
                      {row.description}
                    </ReactMarkdown>
                  </Box>
                )}
              </Box>
            ))}
          </Box>
        )}

        {education.length > 0 && (
          <Box sx={rpStyles.sectionBlock}>
            <SectionTitle>Education</SectionTitle>
            {education.map(row => (
              <Box key={row.id} sx={rpStyles.itemBlock}>
                <Typography sx={rpStyles.educationTitle}>
                  {row.title}
                </Typography>
                {row.dates && (
                  <Typography variant="body2" sx={rpStyles.educationDates}>
                    {row.dates}
                  </Typography>
                )}
                {row.description && (
                  <Box sx={rpStyles.educationMarkdown}>
                    <ReactMarkdown remarkPlugins={[remarkGfm]}>
                      {row.description}
                    </ReactMarkdown>
                  </Box>
                )}
              </Box>
            ))}
          </Box>
        )}

        {skills.length > 0 && (
          <Box sx={rpStyles.sectionBlock}>
            <SectionTitle>Skills</SectionTitle>
            <Box component="ul" sx={rpStyles.skillsList}>
              {skills.map((skill, skillIndex) => (
                <Typography
                  key={`${skill}-${skillIndex}`}
                  component="li"
                  sx={rpStyles.skillItem}
                >
                  {skill}
                </Typography>
              ))}
            </Box>
          </Box>
        )}

        {affiliations.length > 0 && (
          <Box sx={rpStyles.affiliationsSection}>
            <SectionTitle>Professional Affiliations</SectionTitle>
            {affiliations.map(row => (
              <Box key={row.id} sx={rpStyles.itemBlock}>
                <Typography sx={rpStyles.affiliationTitle}>
                  {row.title}
                </Typography>
                {row.duration && (
                  <Typography sx={rpStyles.affiliationDuration}>
                    {row.duration}
                  </Typography>
                )}
              </Box>
            ))}
          </Box>
        )}
      </Box>
    </Box>
  )
}
