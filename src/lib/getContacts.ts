export interface Contact {
  id: string
  displayName: string
  contactType: string
  logo: string
}

export function getContacts(): Contact[] {
  return [
    {
      id: '0',
      displayName: 'Freewallet Team',
      contactType: 'Organization',
      logo: 'FT'
    },
    {
      id: '1',
      displayName: 'InterOp Alliance',
      contactType: 'Organization',
      logo: 'IA'
    },
    {
      id: '2',
      displayName: 'Alex Smith',
      contactType: 'Individual',
      logo: 'AS'
    }
  ]
}
