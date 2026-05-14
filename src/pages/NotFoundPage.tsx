import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Typography from '@mui/material/Typography'
import { Link as RouterLink } from 'react-router'
import { useTranslation } from 'react-i18next'
import { notFoundStyles } from '@/styles/appStyles'

export function NotFoundPage() {
  const { t } = useTranslation()
  return (
    <Box component="main" sx={notFoundStyles.page}>
      <Typography variant="h1" component="h1" sx={{ fontWeight: 600 }}>
        404
      </Typography>
      <Typography variant="h5" color="text.secondary">
        {t('notFound.title')}
      </Typography>
      <Button component={RouterLink} to="/" variant="outlined" sx={{ mt: 2 }}>
        {t('notFound.goHome')}
      </Button>
    </Box>
  )
}
