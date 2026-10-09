import assert from 'node:assert/strict'
import test, { describe } from 'node:test'

import { createStore } from '../src/store.js'

describe('store', () => {
  test('returns what was stored', () => {
    const store = createStore()
    store.set('k', { hello: 'world' }, 1000)
    assert.deepEqual(store.get('k'), { hello: 'world' })
  })

  test('returns undefined for an unknown key', () => {
    assert.equal(createStore().get('nope'), undefined)
  })

  test('expires an entry once its ttl has passed', async () => {
    const store = createStore()
    store.set('k', 'value', 10)
    assert.equal(store.get('k'), 'value')

    await new Promise((resolve) => setTimeout(resolve, 25))
    assert.equal(store.get('k'), undefined)
  })

  test('deletes on demand', () => {
    const store = createStore()
    store.set('k', 'value', 1000)
    store.delete('k')
    assert.equal(store.get('k'), undefined)
  })

  test('overwrites an existing key', () => {
    const store = createStore()
    store.set('k', 'first', 1000)
    store.set('k', 'second', 1000)
    assert.equal(store.get('k'), 'second')
  })

  test('does not hold the process open', () => {
    // The sweep timer is unref'd; if it were not, this test file would hang
    // instead of exiting.
    createStore({ sweepIntervalMs: 1_000_000 })
  })
})
