import { useEffect, useState } from 'react'
import Markdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import { docsStyles } from '@/styles/appStyles'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { SERVER_URL } from '@/app.config'
interface DocContentProps {
  fileName: string
  onError?: () => void
}

export function DocContent({ fileName, onError }: DocContentProps) {
  const [content, setContent] = useState<string | null>(null)
  const [notFound, setNotFound] = useState(false)

  useEffect(() => {
    const target = new URL(
      `docs/${fileName}.md`,
      new URL(SERVER_URL, window.location.origin)
    ).href

    async function load() {
      try {
        const res = await fetch(target, {
          headers: { Accept: 'text/plain' }
        })
        if (!res.ok) {
          setNotFound(true)
          onError?.()
          return
        }
        setContent(await res.text())
      } catch (err: any) {
        console.error(err)
        setNotFound(true)
        onError?.()
      }
    }
    load()
  }, [fileName, onError])

  if (notFound) {
    return (
      <Typography color="error" sx={{ py: 4 }}>
        Document not found.
      </Typography>
    )
  }

  if (content === null) {
    return <LoadingSpinner />
  }

  return (
    <Box sx={docsStyles.content}>
      <Markdown remarkPlugins={[remarkGfm]}>{content}</Markdown>
    </Box>
  )
}
