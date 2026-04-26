declare const __APP_VERSION__: string

declare module '@digitalbazaar/webkms-client'

declare module '@digitalcredentials/ed25519-signature-2020'
declare module '@digitalcredentials/http-client' {
  interface HttpClientResponse extends Response {
    data?: any
  }
  interface HttpClient {
    get(url: string, options?: Record<string, any>): Promise<HttpClientResponse>
    post(url: string, options?: Record<string, any>): Promise<HttpClientResponse>
    put(url: string, options?: Record<string, any>): Promise<HttpClientResponse>
    delete(url: string, options?: Record<string, any>): Promise<HttpClientResponse>
  }
  export const httpClient: HttpClient
}

declare module 'credential-handler-polyfill' {
  export function load(mediator: string): Promise<void>
  export function loadOnce(mediator: string): Promise<void>
}

declare module 'web-credential-handler' {
  export function installHandler(): Promise<void>
  export function receiveCredentialEvent(): Promise<any>
  export function activateHandler(options: {
    mediatorOrigin?: string
    get?(event: unknown): Promise<{ type: string; url: string }>
    store?(event: unknown): Promise<{ type: string; url: string }>
  }): Promise<void>
}
