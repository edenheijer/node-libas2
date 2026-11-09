// Tests added by the WG Den Heijer fork: round trips with two identities, tamper/forgery detection, PKCS#1 v1.5
// key transport, OpenSSL interop in both directions, and live interop with the original libas2 0.5.7
// (devDependency "libas2-legacy", which still runs pkijs 2.4.0 + @peculiar/webcrypto + nodemailer 6.10.1).
import fs from 'fs'
import os from 'os'
import path from 'path'
import { createRequire } from 'module'
import { createHash, publicEncrypt, createPrivateKey, constants, randomBytes } from 'crypto'
import { spawnSync } from 'child_process'
import { describe, test, expect } from 'vitest'
import MimeNode10 from 'nodemailer/lib/mime-node'
import { AS2Composer, AS2Parser, AgreementOptions, rsaPkcs1Unwrap, hasNativeImplicitRejection } from '../core'

const data = (name: string) => path.join(__dirname, 'test-data', name)
const read = (name: string) => fs.readFileSync(data(name), 'utf8')
const local = { cert: read('libas2community.cer'), key: read('libas2community.key'), certPath: data('libas2community.cer'), keyPath: data('libas2community.key') }
const partner = { cert: read('partner.cer'), key: read('partner.key'), certPath: data('partner.cer'), keyPath: data('partner.key') }

const payload = Buffer.from(
  "UNA:+.? 'UNB+UNOC:3+8712345678901:14+8798765432109:14+261109:1200+7'NAD+DP+8712345678901::9++Café Ölçü'UNZ+1+7'\r\n",
  'utf8'
)

// "local" sends to "partner": signed, optionally encrypted, signed MDN requested.
const sendAgreement = (encrypt = true): AgreementOptions => ({
  host: { name: 'LOCAL', id: 'LOCAL', certificate: local.cert, privateKey: local.key, sign: true, decrypt: true, mdn: { signing: 'sha-256' } },
  partner: { name: 'PARTNER', id: 'PARTNER', certificate: partner.cert, encrypt, verify: true }
})
// "partner" receives from "local" and answers with a signed MDN.
const receiveAgreement = (decrypt = true): AgreementOptions => ({
  host: { name: 'PARTNER', id: 'PARTNER', certificate: partner.cert, privateKey: partner.key, decrypt, sign: true },
  partner: { name: 'LOCAL', id: 'LOCAL', certificate: local.cert, verify: true, mdn: { signing: 'sha-256' } }
})

async function compose (agreement: AgreementOptions, content: Buffer | string = payload, contentType = 'application/edifact') {
  const node = await new AS2Composer({ agreement, message: { content, filename: 'order.edi', contentType } }).compile()
  return await node.buildObject()
}

// As an HTTP server would hand a request to the parser.
const receive = (message: { headers: any, body: string }) => AS2Parser.parse({ headers: message.headers, content: Buffer.from(message.body) })

describe('round trip', () => {
  test('signed + encrypted message decrypts, verifies and yields the original payload', async () => {
    const message = await compose(sendAgreement())
    const { contentNode, disposition } = await (await receive(message)).dispositionOut({ agreement: receiveAgreement() })

    expect(disposition.notification.disposition.processed).toBe(true)
    expect(disposition.notification.disposition.description).toBeUndefined()
    expect(Buffer.compare(contentNode.content as Buffer, payload)).toBe(0)
  })

  test('signed MDN verifies with dispositionIn and carries the MIC of the signed content', async () => {
    const message = await compose(sendAgreement())
    const { dispositionNode, disposition } = await (await receive(message)).dispositionOut({ agreement: receiveAgreement() })
    const mdn = await dispositionNode.buildObject()
    expect(mdn.headers['Content-Type']).toContain('micalg=sha-256')

    // Independent MIC: SHA-256 over the signed MIME part (headers + body) minus the delimiter CRLF.
    const decrypted = await (await receive(message)).decrypt({ cert: partner.cert, key: partner.key })
    const signedPart = Buffer.from(decrypted.childNodes[0].raw, 'latin1')
    const expectedMic = createHash('sha256').update(signedPart.subarray(0, signedPart.length - 2)).digest('base64')

    const incoming = await (await AS2Parser.parse({ headers: mdn.headers, content: mdn.body })).dispositionIn({ cert: partner.cert })
    expect(incoming.notification.disposition.processed).toBe(true)
    expect(incoming.notification.originalMessageId).toBe(message.headers['Message-ID'])
    expect(incoming.notification.receivedContentMic).toEqual({ mic: expectedMic, algorithm: 'sha-256' })
    expect(disposition.notification.receivedContentMic.mic).toBe(expectedMic)

    await expect((await AS2Parser.parse({ headers: mdn.headers, content: mdn.body })).dispositionIn({ cert: local.cert })).rejects.toThrow('Could not verify signature')
  })

  test('a tampered payload fails signature verification', async () => {
    const message = await compose(sendAgreement(false))
    const original = Buffer.from(payload).toString('base64').slice(0, 20)
    const tampered = { ...message, body: message.body.replace(original, original.slice(0, 19) + (original[19] === 'A' ? 'B' : 'A')) }
    expect(tampered.body).not.toBe(message.body)

    const { contentNode, disposition } = await (await receive(tampered)).dispositionOut({ agreement: receiveAgreement(false) })
    expect(disposition.notification.disposition.processed).toBe(false)
    expect(disposition.notification.disposition.description?.text).toBe('Could not verify signature')
    expect(contentNode).toBeUndefined()

    const ok = await (await receive(message)).dispositionOut({ agreement: receiveAgreement(false) })
    expect(ok.disposition.notification.disposition.processed).toBe(true)
  })

  test('a signature from a certificate other than the configured partner is rejected', async () => {
    const forged = await compose({ ...sendAgreement(false), host: { ...sendAgreement(false).host, certificate: partner.cert, privateKey: partner.key } })
    const { disposition } = await (await receive(forged)).dispositionOut({ agreement: receiveAgreement(false) })
    expect(disposition.notification.disposition.processed).toBe(false)
  })

  test('binary (Content-Transfer-Encoding: binary) S/MIME bodies survive parsing byte for byte', async () => {
    const message = await compose(sendAgreement())
    const headers = { ...message.headers, 'Content-Transfer-Encoding': 'binary' }

    const { contentNode, disposition } = await (await AS2Parser.parse({ headers, content: Buffer.from(message.body, 'base64') })).dispositionOut({ agreement: receiveAgreement() })
    expect(disposition.notification.disposition.processed).toBe(true)
    expect(Buffer.compare(contentNode.content as Buffer, payload)).toBe(0)
  })
})

describe('RSAES-PKCS1-v1_5 key transport unwrap', () => {
  const partnerKey = createPrivateKey(partner.key)

  test('recovers a content key wrapped with PKCS#1 v1.5 padding', () => {
    const cek = randomBytes(32)
    const wrapped = publicEncrypt({ key: partner.cert, padding: constants.RSA_PKCS1_PADDING }, cek)
    expect(Buffer.from(rsaPkcs1Unwrap(partnerKey, wrapped, 32))).toEqual(cek)
  })

  // Hand-built encoded blocks, RSA-encrypted without padding, to hit each rejection rule.
  const modulusBytes = partnerKey.asymmetricKeyDetails!.modulusLength! / 8
  const block = ({ type = 2, padding = modulusBytes - 3 - 32, key = randomBytes(32) } = {}) => {
    const ps = Buffer.alloc(padding)
    for (let i = 0; i < ps.length; i++) ps[i] = 1 + (randomBytes(1)[0] % 255) // nonzero
    const em = Buffer.concat([Buffer.from([0, type]), ps, Buffer.from([0]), key])
    expect(em.length).toBe(modulusBytes)
    return { key, wrapped: publicEncrypt({ key: partner.cert, padding: constants.RSA_NO_PADDING }, em) }
  }
  const expectRandom = (wrapped: Buffer, keyLength: number, notEqual?: Buffer) => {
    const a = Buffer.from(rsaPkcs1Unwrap(partnerKey, wrapped, keyLength))
    const b = Buffer.from(rsaPkcs1Unwrap(partnerKey, wrapped, keyLength))
    expect(a.length).toBe(keyLength)
    expect(a.equals(b)).toBe(false) // a fresh random key each time, never an error
    if (notEqual) expect(a.subarray(0, notEqual.length).equals(notEqual)).toBe(false)
  }

  test('accepts a hand-built valid block', () => {
    const { key, wrapped } = block()
    expect(Buffer.from(rsaPkcs1Unwrap(partnerKey, wrapped, 32))).toEqual(key)
  })

  test('a well-formed block with the wrong key length yields a random key (RFC 3218)', () => {
    const wrapped = publicEncrypt({ key: partner.cert, padding: constants.RSA_PKCS1_PADDING }, randomBytes(16))
    expectRandom(wrapped, 32)
    const { key, wrapped: longer } = block({ padding: modulusBytes - 3 - 48, key: randomBytes(48) })
    expectRandom(longer, 32, key.subarray(16))
  })

  test('a block with the wrong block type yields a random key', () => {
    const { key, wrapped } = block({ type: 1 })
    expectRandom(wrapped, 32, key)
  })

  test('a block with fewer than 8 padding bytes yields a random key', () => {
    const { key, wrapped } = block({ padding: 7, key: randomBytes(modulusBytes - 3 - 7) })
    expectRandom(wrapped, key.length, key)
  })

  test(`native implicit rejection is ${hasNativeImplicitRejection() ? 'available and used' : 'unavailable here, so the constant-time JS path is used'}`, () => {
    expect(typeof hasNativeImplicitRejection()).toBe('boolean')
  })
})

const hasOpenssl = spawnSync('openssl', ['version']).status === 0
describe.skipIf(!hasOpenssl)('interop with OpenSSL', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'as2-openssl-'))
  // Output goes through -out files: piping binary through stdout gets newline-translated on Windows builds.
  const openssl = (args: string[], out: string) => {
    const result = spawnSync('openssl', [args[0], '-out', path.join(tmp, out), ...args.slice(1)])
    if (result.status !== 0) throw new Error(`openssl ${args.join(' ')}: ${result.stderr}`)
    return fs.readFileSync(path.join(tmp, out))
  }

  test('OpenSSL decrypts and verifies what we send', async () => {
    const message = await compose(sendAgreement())
    fs.writeFileSync(path.join(tmp, 'out.p7m'), Buffer.from(message.body, 'base64'))

    openssl(['cms', '-decrypt', '-binary', '-inform', 'DER', '-in', path.join(tmp, 'out.p7m'), '-recip', partner.certPath, '-inkey', partner.keyPath], 'signed.eml')
    const verified = openssl(['cms', '-verify', '-noverify', '-in', path.join(tmp, 'signed.eml'), '-certfile', local.certPath, '-nointern'], 'verified.eml')
    // Text-mode output on Windows builds turns CRLF into CR CR LF; the verification itself is what matters here.
    const part = await AS2Parser.parse(verified.toString('latin1').replace(/\r+\n/g, '\r\n'))
    expect(Buffer.compare(part.content as Buffer, payload)).toBe(0)
  })

  test('OpenSSL verifies our signed MDN (libas2 0.5.7 MDNs failed this)', async () => {
    const { dispositionNode } = await (await receive(await compose(sendAgreement()))).dispositionOut({ agreement: receiveAgreement() })
    fs.writeFileSync(path.join(tmp, 'mdn.eml'), await dispositionNode.build())
    openssl(['cms', '-verify', '-noverify', '-in', path.join(tmp, 'mdn.eml'), '-certfile', partner.certPath, '-nointern'], 'mdn-content.eml')
  })

  test('we decrypt and verify what OpenSSL sends (PKCS#1 v1.5 key transport, binary transfer encoding)', async () => {
    fs.writeFileSync(path.join(tmp, 'part.eml'), Buffer.concat([Buffer.from('Content-Type: application/edifact\r\nContent-Transfer-Encoding: binary\r\n\r\n'), payload]))
    openssl(['cms', '-sign', '-binary', '-crlfeol', '-md', 'sha256', '-in', path.join(tmp, 'part.eml'), '-signer', local.certPath, '-inkey', local.keyPath], 'signed-in.eml')
    const encrypted = openssl(['cms', '-encrypt', '-binary', '-aes256', '-outform', 'DER', '-in', path.join(tmp, 'signed-in.eml'), partner.certPath], 'in.p7m')

    const headers = {
      'content-type': 'application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"',
      'content-transfer-encoding': 'binary',
      'as2-from': 'LOCAL', 'as2-to': 'PARTNER', 'message-id': '<openssl@test>'
    }
    const { contentNode, disposition } = await (await AS2Parser.parse({ headers, content: encrypted })).dispositionOut({ agreement: receiveAgreement() })
    expect(disposition.notification.disposition.description).toBeUndefined()
    expect(disposition.notification.disposition.processed).toBe(true)
    // As in libas2 0.5.7, a non-base64 part's content keeps the CRLF that precedes the next boundary.
    expect(Buffer.compare(contentNode.content as Buffer, Buffer.concat([payload, Buffer.from('\r\n')]))).toBe(0)
  })
})

describe('interop with the original libas2 0.5.7', () => {
  const legacyRequire = createRequire(require.resolve('libas2-legacy'))
  // The @peculiar/webcrypto monkeypatch applications needed for libas2 0.5.7 to sign at all.
  const { Crypto } = legacyRequire('@peculiar/webcrypto')
  const subtle = Object.getPrototypeOf(new Crypto().subtle)
  let lastDigest = 'SHA-256'
  const digest = subtle.digest
  subtle.digest = function (algorithm: any, input: any) {
    if (algorithm) lastDigest = typeof algorithm === 'string' ? algorithm : algorithm.name ?? lastDigest
    return digest.call(this, algorithm, input)
  }
  const importKey = subtle.importKey
  subtle.importKey = function (format: any, keyData: any, algorithm: any, extractable: any, usages: string[]) {
    if (algorithm && (algorithm === 'RSAES-PKCS1-v1_5' || algorithm.name === 'RSAES-PKCS1-v1_5') && usages.includes('sign')) {
      algorithm = { ...(typeof algorithm === 'object' ? algorithm : {}), name: 'RSASSA-PKCS1-v1_5', hash: { name: lastDigest } }
    }
    return importKey.call(this, format, keyData, algorithm, extractable, usages)
  }
  const legacy = legacyRequire('libas2-legacy') as typeof import('../core')

  const cases: Array<[string, Buffer | string, string]> = [
    ['EDIFACT (base64 part)', payload, 'application/edifact'],
    ['text/plain (7bit part)', 'This is an AS2 connectivity test message.\r\nFrom: LOCAL\r\n', 'text/plain']
  ]

  // Both versions keep the CRLF before the next boundary in a non-base64 (7bit) part's content.
  const expected = (content: Buffer | string, contentType: string) => content.toString() + (contentType === 'text/plain' ? '\r\n' : '')

  for (const [label, content, contentType] of cases) {
    test(`old composes, new receives; MDNs cross-verify: ${label}`, async () => {
      const message = await (await new legacy.AS2Composer({ agreement: sendAgreement() as any, message: { content, filename: 'order.edi', contentType } }).compile()).buildObject()

      const oldOut = await (await legacy.AS2Parser.parse({ headers: message.headers, content: Buffer.from(message.body) })).dispositionOut({ agreement: receiveAgreement() as any })
      const newOut = await (await receive(message)).dispositionOut({ agreement: receiveAgreement() })

      expect(newOut.disposition.notification.disposition.processed).toBe(true)
      expect((newOut.contentNode.content as Buffer).toString('utf8')).toBe(expected(content, contentType))
      if (contentType === 'text/plain') {
        // libas2 0.5.7 signs one CRLF too few on CRLF-terminated parts and so rejects its own message.
        expect(oldOut.disposition.notification.disposition.processed).toBe(false)
      } else {
        expect(newOut.disposition.notification.receivedContentMic.mic).toBe(oldOut.disposition.notification.receivedContentMic.mic)
      }

      // An MDN signed by libas2 0.5.7 verifies here (whatever it reports).
      const oldMdn = await oldOut.dispositionNode.buildObject()
      const inNew = await (await AS2Parser.parse({ headers: oldMdn.headers, content: oldMdn.body })).dispositionIn({ cert: partner.cert })
      expect(inNew.notification.disposition.processed).toBe(oldOut.disposition.notification.disposition.processed)
    })

    test(`new composes, old receives; old verifies our MDN: ${label}`, async () => {
      const message = await compose(sendAgreement(), content, contentType)

      const oldOut = await (await legacy.AS2Parser.parse({ headers: message.headers, content: Buffer.from(message.body) })).dispositionOut({ agreement: receiveAgreement() as any })
      expect(oldOut.disposition.notification.disposition.processed).toBe(true)
      expect(Buffer.from(oldOut.contentNode.content as Buffer).toString('utf8')).toBe(expected(content, contentType))

      const newOut = await (await receive(message)).dispositionOut({ agreement: receiveAgreement() })
      expect(newOut.disposition.notification.receivedContentMic.mic).toBe(oldOut.disposition.notification.receivedContentMic.mic)

      const newMdn = await newOut.dispositionNode.buildObject()
      const inOld = await (await legacy.AS2Parser.parse({ headers: newMdn.headers, content: newMdn.body })).dispositionIn({ cert: partner.cert })
      expect(inOld.notification.disposition.processed).toBe(true)
    })
  }

  test('nodemailer 10 MimeNode serializes every AS2 node shape byte-for-byte like nodemailer 6.10.1', async () => {
    const MimeNode6 = legacyRequire('nodemailer/lib/mime-node')
    const fixed = [{ key: 'Date', value: 'Mon, 09 Nov 2026 12:00:00 +0000' }, { key: 'Message-ID', value: '<abc-123@host.example>' }]
    const as2 = [{ key: 'AS2-From', value: 'WG DEN HEIJER' }, { key: 'AS2-To', value: '"Partner X"' }, { key: 'AS2-Version', value: '1.0' },
      { key: 'Disposition-Notification-Options', value: 'signed-receipt-protocol=required,pkcs7-signature; signed-receipt-micalg=required,sha-256' }]
    const signature = randomBytes(1500)
    const mk = (M: any, contentType: string, opts: { filename?: string, content?: any, headers?: any[] } = {}) => {
      const node = new M(contentType, { filename: opts.filename, baseBoundary: 'fixedbase' })
      node.boundaryPrefix = '--LibAs2'
      if (opts.content !== undefined) node.setContent(opts.content)
      if (opts.headers) node.setHeader(opts.headers)
      return node
    }
    const shapes: Array<(M: any) => any> = [
      M => mk(M, 'application/edi-x12', { filename: 'msg<1@x>.edi', content: payload, headers: [...fixed, ...as2] }),
      M => mk(M, 'text/plain', { filename: 'connectivity-test.txt', content: 'This is a test.\r\nFrom: A\r\n', headers: fixed }),
      M => mk(M, 'text/plain', { content: 'y'.repeat(300) + '\r\nÄÖÜ é\r\n', headers: fixed }),
      M => mk(M, 'application/pkcs7-mime; smime-type=enveloped-data', { filename: 'smime.p7m', content: signature, headers: [...fixed, ...as2] }),
      M => {
        const root = mk(M, 'multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;', { headers: fixed })
        root.appendChild(mk(M, 'application/edi-x12', { filename: 'a.edi', content: payload }))
        root.appendChild(mk(M, 'application/pkcs7-signature', { filename: 'smime.p7s', content: signature }))
        return root
      },
      M => {
        const root = mk(M, 'multipart/report; report-type=disposition-notification', { headers: fixed })
        root.appendChild(mk(M, 'text/plain', { content: 'The message was received successfully. This is no guarantee that the message contents have been processed.' }))
        root.appendChild(mk(M, 'message/disposition-notification', { content: 'Final-Recipient: rfc822; X\r\nDisposition: automatic-action/MDN-sent-automatically; processed\r\n' }))
        return root
      }
    ]

    for (const shape of shapes) {
      expect((await shape(MimeNode10).build()).toString('latin1')).toBe((await shape(MimeNode6).build()).toString('latin1'))
    }
  })
})
