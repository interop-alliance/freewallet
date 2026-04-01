import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import { sectionHeaderStyles, infoBlockRoot, infoBlockValue } from '@/styles/credentialStyles'

export function InfoBlock({ header, value }: { header: string; value: string }) {
  return (
    <Box sx={infoBlockRoot}>
      <SectionHeader>{header}</SectionHeader>
      <Typography variant="body2" sx={infoBlockValue}>
        {value}
      </Typography>
    </Box>
  )
}

export function SectionHeader({ children }: { children: React.ReactNode }) {
  return (
    <Typography variant="overline" sx={sectionHeaderStyles}>
      {children}
    </Typography>
  )
}
