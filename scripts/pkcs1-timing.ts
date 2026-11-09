// Timing check for rsaPkcs1Unwrap: median time for valid vs invalid (bad padding) blocks, interleaved so drift
// affects both equally. Compares against the v0.5.8-wgdh.1 implementation. Run: npx tsx scripts/pkcs1-timing.ts
import fs from 'fs'
import path from 'path'
import { createPrivateKey, privateDecrypt, publicEncrypt, randomBytes, constants, KeyObject } from 'crypto'
import { rsaPkcs1Unwrap, hasNativeImplicitRejection } from '../src/AS2Crypto/AS2EnvelopedData'

const runs = Number(process.argv[2] ?? 3000)
const dir = path.join(__dirname, '..', 'test', 'test-data')
const cert = fs.readFileSync(path.join(dir, 'partner.cer'), 'utf8')
const key = createPrivateKey(fs.readFileSync(path.join(dir, 'partner.key'), 'utf8'))

// v0.5.8-wgdh.1, for comparison.
function previous (privateKey: KeyObject, encryptedKey: Uint8Array, keyLength: number) {
  const em = privateDecrypt({ key: privateKey, padding: constants.RSA_NO_PADDING }, encryptedKey)
  const separator = em.indexOf(0, 2)
  const valid = em[0] === 0 && em[1] === 2 && separator >= 10 && em.length - separator - 1 === keyLength
  return valid ? em.subarray(separator + 1) : randomBytes(keyLength)
}

const valid = publicEncrypt({ key: cert, padding: constants.RSA_PKCS1_PADDING }, randomBytes(32))
const invalid = publicEncrypt({ key: cert, padding: constants.RSA_NO_PADDING }, Buffer.concat([Buffer.from([0, 1]), randomBytes(254)]))

function measure (fn: (k: KeyObject, c: Uint8Array, n: number) => unknown) {
  const times: Record<'valid' | 'invalid', number[]> = { valid: [], invalid: [] }
  for (let i = 0; i < 200; i++) { fn(key, valid, 32); fn(key, invalid, 32) } // warm-up
  for (let i = 0; i < runs; i++) {
    for (const [name, input] of (i % 2 ? [['valid', valid], ['invalid', invalid]] : [['invalid', invalid], ['valid', valid]]) as Array<['valid' | 'invalid', Buffer]>) {
      const start = process.hrtime.bigint()
      fn(key, input, 32)
      times[name].push(Number(process.hrtime.bigint() - start) / 1000)
    }
  }
  const median = (xs: number[]) => xs.sort((a, b) => a - b)[Math.floor(xs.length / 2)]
  const v = median(times.valid)
  const x = median(times.invalid)
  return `valid ${v.toFixed(1)} µs, invalid ${x.toFixed(1)} µs, difference ${(x - v).toFixed(1)} µs`
}

console.log(`Node ${process.version}, OpenSSL ${process.versions.openssl}, native implicit rejection: ${hasNativeImplicitRejection()}, ${runs} interleaved runs each`)
console.log('v0.5.8-wgdh.1:', measure(previous))
console.log('current      :', measure(rsaPkcs1Unwrap))
console.log('raw RSA only :', measure((k, c) => privateDecrypt({ key: k, padding: constants.RSA_NO_PADDING }, c)))
