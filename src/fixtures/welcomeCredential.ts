import type { IVerifiableCredential } from '@interop/data-integrity-core'

export const welcomeCredential: IVerifiableCredential = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2"
  ],
  "type": [
    "VerifiableCredential"
  ],
  "name": "Your First Credential",
  "credentialSubject": {
    "description": "You have successfully set up your credentials wallet!"
  },
  "issuer": "did:web:interopalliance.org",
  "proof": {
    "type": "DataIntegrityProof",
    "created": "2026-06-24T21:50:04Z",
    "verificationMethod": "did:web:interopalliance.org#z6Mkk1sCE6ve9wFJzaYeWZhhmW5Mke37N8ahhbovdkofUuEs",
    "cryptosuite": "eddsa-rdfc-2022",
    "proofPurpose": "assertionMethod",
    "proofValue": "z2QRmiw7gnqV6JPSYfPVLan7eHAjL7eC4fALF4sGzd9uJJiBoUdNs43xHfw9J5RTPDAE2zk9Ao3GsB7bjbuzFcuN4"
  }
}
