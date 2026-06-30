declare const __APP_VERSION__: string

declare module 'credential-handler-polyfill' {
  export function load(mediator: string): Promise<void>
  export function loadOnce(mediator: string): Promise<void>
}

declare module 'web-credential-handler' {
  export function installHandler(): Promise<void>
  export function receiveCredentialEvent(): Promise<unknown>
  export function activateHandler(options: {
    mediatorOrigin?: string
    get?(event: unknown): Promise<{ type: string; url: string }>
    store?(event: unknown): Promise<{ type: string; url: string }>
  }): Promise<void>
}
