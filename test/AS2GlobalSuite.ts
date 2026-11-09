import { AS2MimeNode, getPackageJson, isMdn, request } from '../core'
import * as fs from 'fs'
import * as assert from 'assert'
import nock from 'nock'
import { syncBuiltinESMExports } from 'module'
import * as os from 'os'
import * as path from 'path'

describe('Globals for libas2', () => {
  it('should return empty package json', async () => {
    // Fork: ESM namespaces cannot be stubbed under vitest; start the search where no package.json exists.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'libas2-'))
    const pkg = getPackageJson(path.join(dir, 'a', 'b', 'c', 'd', 'e', 'file.js'))

    assert.deepStrictEqual(pkg, {})
  })

  it('should make requests', async () => {
    const payload: any = { tested: null }

    const scope = nock('http://local.host')

    scope.post(uri => uri.startsWith('/fake')).reply(200, payload)
    scope.post(uri => uri.startsWith('/fake')).reply(200, 'payload')
    syncBuiltinESMExports() // fork: let vitest's ESM view of node:http see nock's patch

    const response = await request({
      url: 'http://local.host/fake',
      params: {
        test1: 1,
        test2: null
      }
    })
    const response2 = await request({ url: 'http://local.host/fake' })

    assert.deepStrictEqual(response.json(), payload)
    assert.strictEqual(response2.json() instanceof Error, true)
  })

  it('should check if AS2MimeNode is a MDN', () => {
    const mime = new AS2MimeNode({})

    assert.strictEqual(isMdn(mime), false)
  })
})
