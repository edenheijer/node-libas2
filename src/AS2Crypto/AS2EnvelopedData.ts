import { randomBytes, createPrivateKey, privateDecrypt, publicEncrypt, generateKeyPairSync, constants, KeyObject } from 'crypto'
import { PemFile } from './PemFile'
import { ObjectID } from './LibOid'
import { AS2Encryption } from './Interfaces'
import { load, toArrayBuffer } from './Engine'

const RSA_ENCRYPTION = '1.2.840.113549.1.1.1'

let nativeImplicitRejection: boolean | undefined

/** Whether Node's privateDecrypt accepts RSA_PKCS1_PADDING, which it only does when its OpenSSL implements
 * implicit rejection (OpenSSL 3.2+; Node refuses it otherwise since CVE-2023-46809). Probed once, then cached. */
export function hasNativeImplicitRejection (): boolean {
  if (nativeImplicitRejection === undefined) {
    try {
      const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 })
      const probe = Buffer.from('libas2 implicit rejection probe')
      const wrapped = publicEncrypt({ key: publicKey, padding: constants.RSA_PKCS1_PADDING }, probe)
      nativeImplicitRejection = privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_PADDING }, wrapped).equals(probe)
    } catch {
      nativeImplicitRejection = false
    }
  }

  return nativeImplicitRejection
}

/** Branch-free: 1 when x === 0, else 0 (for |x| < 2^31). */
const isZero = (x: number): number => ((x | -x) >>> 31) ^ 1

/** Copies `candidate` (or zeros past its end) when ok === 1, else `fallback`, without branching on ok. */
function select (candidate: Uint8Array, fallback: Uint8Array, ok: number, offset = 0): ArrayBuffer {
  const mask = -ok & 0xff
  const out = new Uint8Array(fallback.length)

  for (let i = 0; i < out.length; i++) {
    out[i] = ((candidate[offset + i] | 0) & mask) | (fallback[i] & ~mask)
  }

  return out.buffer
}

/**
 * RSAES-PKCS1-v1_5 key transport unwrap (RFC 8017 7.2.2) for CMS content-encryption keys. Node's WebCrypto has no
 * RSAES-PKCS1-v1_5, so this does not go through pkijs. Any failure (bad padding, wrong key length) yields a random
 * key of the expected length instead of an error (RFC 3218 2.3.2), so it only surfaces later as an undecryptable
 * payload.
 *
 * - With OpenSSL implicit rejection available (see hasNativeImplicitRejection) Node does the unpadding itself.
 * - Otherwise the raw RSA result is unpadded here in one full, branch-free pass over the block, so valid and
 *   invalid blocks take the same path (Bleichenbacher/Marvin timing oracle).
 * The fallback key is drawn before decrypting and the result is chosen by mask in both cases.
 */
export function rsaPkcs1Unwrap (privateKey: KeyObject, encryptedKey: Uint8Array, keyLength: number): ArrayBuffer {
  const fallback = randomBytes(keyLength)

  if (hasNativeImplicitRejection()) {
    let message: Buffer = Buffer.alloc(0)
    let decrypted = 1
    try {
      message = privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_PADDING }, encryptedKey)
    } catch {
      decrypted = 0 // not a padding error (those are rejected implicitly) but e.g. a wrong-sized ciphertext
    }
    return select(message, fallback, decrypted & isZero(message.length ^ keyLength))
  }

  const em = privateDecrypt({ key: privateKey, padding: constants.RSA_NO_PADDING }, encryptedKey)
  const k = em.length
  let bad = em[0] | (em[1] ^ 2)
  let separator = 0
  let found = 0

  for (let i = 2; i < k; i++) {
    const zero = isZero(em[i])
    separator |= -(zero & (found ^ 1)) & i // index of the first zero after the 00 02 header
    found |= zero
  }

  bad |= found ^ 1
  bad |= (separator - 10) >>> 31 // at least 8 padding bytes
  bad |= isZero(isZero((k - separator - 1) ^ keyLength)) // exact key length

  return select(em, fallback, isZero(bad), k - keyLength)
}

/** CMS EnvelopedData: RSA key transport (RSA-OAEP when encrypting, as pkijs defaults to; RSA-OAEP or
 * PKCS#1 v1.5 when decrypting) with AES content encryption. Ported from pkijs 2 to pkijs 4. */
export class AS2EnvelopedData {
  /** @param enveloped - Kept for API compatibility; the data is parsed as EnvelopedData when decrypting. */
  constructor (data: Buffer, enveloped: boolean = false) {
    this.data = toArrayBuffer(data)
    this.isEnveloped = enveloped
  }

  data: ArrayBuffer
  isEnveloped: boolean

  private _getEncryptionAlgorithm (encryption: AS2Encryption) {
    switch (encryption) {
      case 'aes128-CBC':
        return { name: 'AES-CBC', length: 128 }
      case 'aes192-CBC':
        return { name: 'AES-CBC', length: 192 }
      case 'aes256-CBC':
        return { name: 'AES-CBC', length: 256 }
      case 'aes128-GCM':
        return { name: 'AES-GCM', length: 128 }
      case 'aes192-GCM':
        return { name: 'AES-GCM', length: 192 }
      case 'aes256-GCM':
        return { name: 'AES-GCM', length: 256 }
      default:
        throw new Error('Unsupported algorithm: ' + encryption)
    }
  }

  async encrypt (cert: string | Buffer | PemFile, encryption: AS2Encryption): Promise<Buffer> {
    const algorithm = this._getEncryptionAlgorithm(encryption)
    const { pkijs, crypto } = await load()
    const enveloped = new pkijs.EnvelopedData()

    enveloped.addRecipientByCertificate(pkijs.Certificate.fromBER(new PemFile(cert).data), undefined, undefined, crypto)
    await enveloped.encrypt(algorithm as Algorithm, this.data, crypto)

    const envelopedDataContent = new pkijs.ContentInfo({
      contentType: new ObjectID({ name: 'envelopedData' }).id,
      content: enveloped.toSchema()
    })

    return Buffer.from(envelopedDataContent.toSchema().toBER())
  }

  async decrypt (cert: string | Buffer | PemFile, key: string | Buffer | PemFile): Promise<Buffer> {
    const { pkijs, crypto } = await load()
    const envelopedDataContent = pkijs.ContentInfo.fromBER(this.data)
    const enveloped = new pkijs.EnvelopedData({ schema: envelopedDataContent.content })
    const recipientCertificate = pkijs.Certificate.fromBER(new PemFile(cert).data)
    const recipientPrivateKey = new PemFile(key).data
    const recipient = enveloped.recipientInfos[0]?.value

    if (recipient instanceof pkijs.KeyTransRecipientInfo && recipient.keyEncryptionAlgorithm.algorithmId === RSA_ENCRYPTION) {
      const contentAlgorithm = crypto.getAlgorithmByOID<AesKeyAlgorithm>(
        enveloped.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId,
        true
      )
      const keyObject = createPrivateKey({ key: Buffer.from(recipientPrivateKey), format: 'der', type: 'pkcs8' })
      // pkijs calls crypto.subtle.decrypt(key.algorithm, key, encryptedKey) with the key and crypto handed in.
      const keyCrypto = {
        subtle: {
          decrypt: async (_algorithm: unknown, _key: unknown, encryptedKey: Uint8Array) =>
            rsaPkcs1Unwrap(keyObject, encryptedKey, contentAlgorithm.length / 8)
        }
      }

      this.data = await enveloped.decrypt(0, {
        recipientCertificate,
        recipientPrivateKey: { algorithm: { name: 'RSAES-PKCS1-v1_5' } } as CryptoKey,
        crypto: keyCrypto as unknown as Crypto
      }, crypto)
    } else {
      this.data = await enveloped.decrypt(0, { recipientCertificate, recipientPrivateKey }, crypto)
    }

    return Buffer.from(this.data)
  }
}
