import { randomBytes, createPrivateKey, privateDecrypt, constants, KeyObject } from 'crypto'
import { PemFile } from './PemFile'
import { ObjectID } from './LibOid'
import { AS2Encryption } from './Interfaces'
import { load, toArrayBuffer } from './Engine'

const RSA_ENCRYPTION = '1.2.840.113549.1.1.1'

/**
 * RSAES-PKCS1-v1_5 key transport unwrap (RFC 8017 7.2.2) for CMS. Node's WebCrypto has no RSAES-PKCS1-v1_5 and
 * Node 20.11+/22 on OpenSSL 3.0 refuse privateDecrypt with RSA_PKCS1_PADDING (CVE-2023-46809), so do the raw RSA
 * operation and strip the padding here. A malformed block yields a random key instead of an error, per RFC 3218
 * section 2.3.2, so a failure surfaces only later as an undecryptable payload and gives no padding oracle.
 */
export function rsaPkcs1Unwrap (privateKey: KeyObject, encryptedKey: Uint8Array, keyLength: number): ArrayBuffer {
  const em = privateDecrypt({ key: privateKey, padding: constants.RSA_NO_PADDING }, encryptedKey)
  const separator = em.indexOf(0, 2)
  const valid = em[0] === 0 && em[1] === 2 && separator >= 10 && em.length - separator - 1 === keyLength

  return toArrayBuffer(valid ? em.subarray(separator + 1) : randomBytes(keyLength))
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
