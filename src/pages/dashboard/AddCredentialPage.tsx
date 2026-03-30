import { useState } from 'react'
import Box from '@mui/material/Box'
import TextField from '@mui/material/TextField'
import Button from '@mui/material/Button'
import { DashboardLayout } from '@/components/DashboardLayout'
import { addCredential } from '@/lib/addCredential'
import { dashboardStyles } from '@/styles/appStyles'

export function AddCredentialPage() {
  const [input, setInput] = useState('')

  function handleAdd() {
    addCredential()
  }

  return (
    <DashboardLayout title="Add Credential">
      <Box sx={dashboardStyles.addCredentialForm}>
        <TextField
          multiline
          minRows={4}
          placeholder="Paste a URL or full credential JSON."
          value={input}
          onChange={e => setInput(e.target.value)}
          fullWidth
        />
        <Button
          variant="outlined"
          onClick={handleAdd}
          sx={dashboardStyles.addCredentialButton}
        >
          Add
        </Button>
      </Box>
    </DashboardLayout>
  )
}
