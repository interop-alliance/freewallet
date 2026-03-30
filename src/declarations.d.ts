declare module '@digitalbazaar/webkms-client'
declare module '@digitalcredentials/ed25519-signature-2020'

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
