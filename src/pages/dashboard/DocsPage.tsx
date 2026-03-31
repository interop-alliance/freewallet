import { useEffect, useState } from 'react'
import { useParams } from 'react-router'
import Markdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import Box from '@mui/material/Box'
import { DashboardLayout } from '@/components/DashboardLayout'
import { docsStyles } from '@/styles/appStyles'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { NotFoundPage } from '@/pages/NotFoundPage'

function DocContent({ fileName }: { fileName: string }) {
  const [content, setContent] = useState<string | null>(null)
  const [notFound, setNotFound] = useState(false)

  useEffect(() => {
    async function load() {
      try {
        const mdFile = await fetch(
          `${import.meta.env.BASE_URL}docs/${fileName}.md`
        )
        if (!mdFile.ok) {
          setNotFound(true)
          return
        }
        setContent(await mdFile.text())
      } catch (error: any) {
        console.error(error)
        setNotFound(true)
      }
    }
    load()
  }, [fileName])

  if (notFound) {
    return <NotFoundPage />
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

export function DocsPage() {
  const { fileName } = useParams()

  if (!fileName) {
    return <NotFoundPage />
  }

  return (
    <DashboardLayout title="">
      <DocContent key={fileName} fileName={fileName} />
    </DashboardLayout>
  )
}
