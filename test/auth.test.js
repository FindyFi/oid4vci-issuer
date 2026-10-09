import assert from 'node:assert/strict'
import test, { describe } from 'node:test'

import { requireCoordinatorToken } from '../src/auth.js'

// Minimal express-shaped req/res doubles - enough for a guard that only
// reads one header and either calls next() or sends a 401.
function invoke(middleware, authorization) {
  const result = { nexted: false, status: undefined, body: undefined }
  const req = { get: (name) => (name.toLowerCase() === 'authorization' ? authorization : undefined) }
  const res = {
    status(code) {
      result.status = code
      return res
    },
    json(payload) {
      result.body = payload
      return res
    },
  }
  middleware(req, res, () => {
    result.nexted = true
  })
  return result
}

describe('requireCoordinatorToken', () => {
  test('accepts a matching bearer token', () => {
    const result = invoke(requireCoordinatorToken('s3cret'), 'Bearer s3cret')
    assert.equal(result.nexted, true)
    assert.equal(result.status, undefined)
  })

  test('rejects a wrong token', () => {
    const result = invoke(requireCoordinatorToken('s3cret'), 'Bearer wrong')
    assert.equal(result.nexted, false)
    assert.equal(result.status, 401)
    assert.deepEqual(result.body, { error: 'unauthorized' })
  })

  test('rejects a missing authorization header', () => {
    const result = invoke(requireCoordinatorToken('s3cret'), undefined)
    assert.equal(result.nexted, false)
    assert.equal(result.status, 401)
  })

  test('rejects a non-bearer scheme', () => {
    const result = invoke(requireCoordinatorToken('s3cret'), 'Basic s3cret')
    assert.equal(result.nexted, false)
    assert.equal(result.status, 401)
  })

  test('rejects a token that is a prefix of the real one', () => {
    const result = invoke(requireCoordinatorToken('s3cret'), 'Bearer s3c')
    assert.equal(result.nexted, false)
    assert.equal(result.status, 401)
  })

  test('rejects a token that merely starts with the real one', () => {
    const result = invoke(requireCoordinatorToken('s3cret'), 'Bearer s3cretXY')
    assert.equal(result.nexted, false)
    assert.equal(result.status, 401)
  })

  test('compares the whole of a long token, not a prefix of it', () => {
    const long = 'x'.repeat(200)
    assert.equal(invoke(requireCoordinatorToken(long), `Bearer ${long}`).nexted, true)
    // Differs only in the last character.
    assert.equal(invoke(requireCoordinatorToken(long), `Bearer ${'x'.repeat(199)}y`).nexted, false)
  })

  test('is disabled when no token is configured', () => {
    // Local dev only - documented in .env.example as unsafe elsewhere.
    const result = invoke(requireCoordinatorToken(undefined), undefined)
    assert.equal(result.nexted, true)
  })
})
