export async function fetchFromURL(url: string): Promise<string> {
  console.log('Fetching credential from URL:', url)
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} ${response.statusText}`)
  }

  const text = await response.text()
  console.log('Fetched credential text, length:', text.length)
  return text.trim()
}
