declare module '@digitalbazaar/webkms-client'

declare module '@digitalbazaar/vc' {
  export function verifyCredential(options: Record<string, unknown>): Promise<{
    verified: boolean
    error?: Error | unknown
    results?: Array<{ verified?: boolean; error?: unknown }>
  }>
}

declare module '@digitalbazaar/data-integrity' {
  export class DataIntegrityProof {
    constructor(options?: Record<string, unknown>)
  }
}

declare module '@digitalbazaar/ed25519-signature-2020' {
  export class Ed25519Signature2020 {
    constructor(options?: Record<string, unknown>)
  }
}

declare module '@digitalbazaar/eddsa-rdfc-2022-cryptosuite' {
  export const cryptosuite: Record<string, unknown>
}

declare module '@digitalbazaar/vc-bitstring-status-list' {
  export function checkStatus(options: Record<string, unknown>): Promise<{
    verified: boolean
    error?: unknown
    results?: Array<{ status?: boolean }>
  }>
  export function statusTypeMatches(options: { credential: unknown }): boolean
}

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
