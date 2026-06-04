import type { IVerifiableCredential } from '@interop/data-integrity-core'

// TODO fix the signature
export const welcomeCredential: IVerifiableCredential = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://w3id.org/security/suites/ed25519-2020/v1'
  ],
  type: ['VerifiableCredential'],
  issuer: 'did:key:z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC',
  name: 'Your First Credential',
  credentialSubject: {
    description: 'You have successfully set up your credentials wallet!'
  },
  proof: {
    type: 'Ed25519Signature2020',
    created: '2025-08-19T06:55:17Z',
    verificationMethod:
      'did:key:z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC#z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC',
    proofPurpose: 'assertionMethod',
    proofValue:
      'z4EiTbmC79r4dRaqLQZr2yxQASoMKneHVNHVaWh1xcDoPG2eTwYjKoYaku1Canb7a6Xp5fSogKJyEhkZCaqQ6Y5nw'
  }
}
