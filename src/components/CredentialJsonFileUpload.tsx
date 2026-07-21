import { useRef, useState, type DragEvent } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import ButtonBase from '@mui/material/ButtonBase'
import Typography from '@mui/material/Typography'
import { MdUploadFile } from 'react-icons/md'
import { useTranslation } from 'react-i18next'
import { credentialJsonUploadStyles } from '@/styles/credentialJsonUploadStyles'
import { isJsonCredentialFile } from '@/lib/resolveCredentialJsonFiles'

const JSON_FILE_ACCEPT = '.json,application/json'

function jsonFilesFrom(fileList: FileList | null): File[] {
  if (!fileList?.length) {
    return []
  }
  return [...fileList].filter(isJsonCredentialFile)
}

type CredentialJsonUploadPanelProps = {
  onFiles: (files: File[]) => void
  disabled?: boolean
}

export function CredentialJsonUploadPanel({
  onFiles,
  disabled = false
}: CredentialJsonUploadPanelProps) {
  const { t } = useTranslation()
  const inputRef = useRef<HTMLInputElement>(null)
  const dragDepthRef = useRef(0)
  const [dragOver, setDragOver] = useState(false)

  function pickFiles() {
    if (!disabled) {
      inputRef.current?.click()
    }
  }

  function emitFiles(fileList: FileList | null) {
    const files = jsonFilesFrom(fileList)
    if (files.length > 0) {
      onFiles(files)
    }
  }

  function handleDragEnter(event: DragEvent) {
    event.preventDefault()
    event.stopPropagation()
    if (!disabled) {
      dragDepthRef.current += 1
      setDragOver(true)
    }
  }

  function handleDragLeave(event: DragEvent) {
    event.preventDefault()
    event.stopPropagation()
    dragDepthRef.current -= 1
    if (dragDepthRef.current <= 0) {
      dragDepthRef.current = 0
      setDragOver(false)
    }
  }

  function handleDragOver(event: DragEvent) {
    event.preventDefault()
    event.stopPropagation()
  }

  function handleDrop(event: DragEvent) {
    event.preventDefault()
    event.stopPropagation()
    dragDepthRef.current = 0
    setDragOver(false)
    if (!disabled) {
      emitFiles(event.dataTransfer.files)
    }
  }

  return (
    <>
      <input
        ref={inputRef}
        type="file"
        accept={JSON_FILE_ACCEPT}
        multiple
        hidden
        onChange={event => {
          emitFiles(event.target.files)
          event.target.value = ''
        }}
      />
      <ButtonBase
        component="div"
        onClick={pickFiles}
        onDragEnter={handleDragEnter}
        onDragLeave={handleDragLeave}
        onDragOver={handleDragOver}
        onDrop={handleDrop}
        disabled={disabled}
        aria-label={t('addCredential.upload.dropHint')}
        sx={credentialJsonUploadStyles.panel(dragOver, disabled)}
      >
        <Box sx={credentialJsonUploadStyles.panelContent}>
          <Box sx={credentialJsonUploadStyles.iconWrap}>
            <MdUploadFile size={40} />
          </Box>
          <Typography variant="h6" sx={{ fontWeight: 600 }}>
            {t('addCredential.upload.title')}
          </Typography>
          <Typography
            variant="body2"
            color="text.secondary"
            sx={{ maxWidth: 360, textAlign: 'center' }}
          >
            {t('addCredential.upload.subtitle')}
          </Typography>
          <Button
            variant="contained"
            size="large"
            disabled={disabled}
            onClick={event => {
              event.stopPropagation()
              pickFiles()
            }}
            sx={credentialJsonUploadStyles.browseButton}
          >
            {t('addCredential.upload.browse')}
          </Button>
        </Box>
      </ButtonBase>
    </>
  )
}
