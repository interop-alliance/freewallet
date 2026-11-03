/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * The root error boundary. A render-time throw anywhere below it would
 * otherwise unmount the whole tree and leave a blank page with no trace,
 * which on a phone browser is undiagnosable. This boundary renders the
 * error's name, message, and stack, plus React's component stack, as plain
 * HTML with inline styles, so it still renders when the theme provider or
 * the i18n layer is what threw. The same error is logged under
 * `fw:ui:error-boundary`.
 */
import { Component, type ErrorInfo, type ReactNode } from 'react'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:error-boundary')

const containerStyle = {
  fontFamily: 'system-ui, sans-serif',
  padding: '16px',
  maxWidth: '100%',
  boxSizing: 'border-box' as const
}

const preStyle = {
  fontSize: '12px',
  whiteSpace: 'pre-wrap' as const,
  wordBreak: 'break-word' as const,
  background: '#f4f4f4',
  color: '#222',
  padding: '8px',
  borderRadius: '4px',
  overflowX: 'auto' as const
}

export class AppErrorBoundary extends Component<
  { children: ReactNode },
  { error: Error | null; componentStack: string | null }
> {
  state = { error: null, componentStack: null }

  static getDerivedStateFromError(error: unknown) {
    return {
      error: error instanceof Error ? error : new Error(String(error))
    }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    log.error('Uncaught render error', {
      err: error,
      componentStack: info.componentStack
    })
    this.setState({ componentStack: info.componentStack ?? null })
  }

  render() {
    const { error, componentStack } = this.state
    if (!error) {
      return this.props.children
    }
    const err = error as Error
    return (
      <div style={containerStyle}>
        <h2 style={{ marginTop: 0 }}>Something went wrong</h2>
        <p>
          Reloading the page clears this. The details below help in reporting
          the problem.
        </p>
        <pre style={preStyle}>
          {err.name}: {err.message}
          {'\n\n'}
          {err.stack ?? '(no stack)'}
          {componentStack ? `\n\nComponent stack:${componentStack}` : ''}
        </pre>
        <button type="button" onClick={() => window.location.reload()}>
          Reload
        </button>
      </div>
    )
  }
}
