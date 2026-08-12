import { describe, expect, it } from 'vitest'
import { flattenSearchValues } from '@/lib/searchValues'

describe('flattenSearchValues', () => {
  it('collects every leaf value as its own entry', () => {
    const values = flattenSearchValues({
      name: 'Alice',
      age: 30,
      active: true,
      nested: { city: 'Boston' }
    })
    expect(values.sort()).toEqual(['30', 'Alice', 'Boston', 'true'])
  })

  it('skips excluded keys', () => {
    const values = flattenSearchValues(
      { name: 'Alice', proof: { jws: 'secret' } },
      ['proof']
    )
    expect(values).toEqual(['Alice'])
  })

  it('handles a very large array without throwing', () => {
    const large = new Array(200_000).fill('x')
    expect(() => flattenSearchValues({ list: large })).not.toThrow()
    expect(flattenSearchValues({ list: large })).toHaveLength(200_000)
  })
})
