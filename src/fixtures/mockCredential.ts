import type { IVerifiableCredential } from '@digitalcredentials/ssi'

export const mockCredential: IVerifiableCredential = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://w3id.org/security/suites/ed25519-2020/v1',
    'https://w3id.org/dcc/v1',
    'https://w3id.org/vc/status-list/2021/v1'
  ],
  type: ['VerifiableCredential', 'Assertion'],
  issuer: {
    id: 'did:key:z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC',
    name: 'Example University',
    url: 'https://cs.example.edu',
    image:
      'https://user-images.githubusercontent.com/947005/133544904-29d6139d-2e7b-4fe2-b6e9-7d1022bb6a45.png'
  },
  issuanceDate: '2020-08-16T12:00:00.000+00:00',
  credentialSubject: {
    id: 'did:key:z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC',
    name: 'Kayode Ezike',
    hasCredential: {
      type: ['EducationalOccupationalCredential'],
      name: 'GT Guide',
      description:
        'The holder of this credential is qualified to lead new student orientations.'
    }
  },
  expirationDate: '2025-08-16T12:00:00.000+00:00',
  credentialStatus: {
    id: 'https://digitalcredentials.github.io/credential-status-playground/JWZM3H8WKU#2',
    type: 'StatusList2021Entry',
    statusPurpose: 'revocation',
    statusListIndex: 2,
    statusListCredential:
      'https://digitalcredentials.github.io/credential-status-playground/JWZM3H8WKU'
  },
  proof: {
    type: 'Ed25519Signature2020',
    created: '2022-08-19T06:55:17Z',
    verificationMethod:
      'did:key:z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC#z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC',
    proofPurpose: 'assertionMethod',
    proofValue:
      'z4EiTbmC79r4dRaqLQZr2yxQASoMKneHVNHVaWh1xcDoPG2eTwYjKoYaku1Canb7a6Xp5fSogKJyEhkZCaqQ6Y5nw'
  }
}
