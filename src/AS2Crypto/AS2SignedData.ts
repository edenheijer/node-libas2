import { PemFile } from './PemFile'
import { ObjectID } from './LibOid'
import { isNullOrUndefined } from '../Helpers'
import { AS2Constants } from '../Constants'
import { load, toArrayBuffer } from './Engine'

const { SIGNING } = AS2Constants

/** Detached CMS SignedData over a canonical MIME part.
 * Ported from pkijs 2 to pkijs 4. Differences from libas2 0.5.7:
 * - the signing key is imported as RSASSA-PKCS1-v1_5 (upstream asked WebCrypto for RSAES-PKCS1-v1_5, which
 *   cannot sign, and needed a @peculiar/webcrypto monkeypatch in applications);
 * - with a certificate given, the signature is verified against THAT certificate instead of the certificate
 *   embedded in the message under the same issuer + serial (which a forger controls);
 * - pkijs 4 throws where pkijs 2 resolved false on a digest mismatch; verify() still resolves false.
 */
export class AS2SignedData {
  constructor (data: Buffer, signedData?: Buffer) {
    this.data = toArrayBuffer(data)
    this.signature = signedData
  }

  data: ArrayBuffer
  signature?: Buffer
  digestInfo?: {
    digest: ArrayBuffer
    algorithm: string
  }

  getMessageDigest (): {
    digest: Buffer
    algorithm: string
  } {
    if (typeof this.digestInfo !== 'undefined') {
      return {
        digest: Buffer.from(this.digestInfo.digest),
        algorithm: this.digestInfo.algorithm
      }
    }

    throw new Error('Message digest not yet calculated.')
  }

  async sign ({ cert, key, algorithm, addSigners }: SignMethodOptions): Promise<Buffer> {
    const { pkijs, asn1js, crypto } = await load()
    const signed = new pkijs.SignedData({
      version: 1,
      encapContentInfo: new pkijs.EncapsulatedContentInfo({
        eContentType: new ObjectID({ name: 'data' }).id
      }),
      signerInfos: [],
      certificates: []
    })
    const signers = [{ cert, key, algorithm }, ...(Array.isArray(addSigners) ? addSigners : [])]

    for (const signer of signers) {
      const hash = isNullOrUndefined(signer.algorithm) ? SIGNING.SHA256 : signer.algorithm
      const certificate = pkijs.Certificate.fromBER(new PemFile(signer.cert).data)
      const messageDigest = await crypto.digest({ name: hash }, this.data)
      const privateKey = await crypto.importKey(
        'pkcs8',
        new PemFile(signer.key).data,
        signingKeyAlgorithm(crypto, certificate, hash) as any,
        true,
        ['sign']
      )

      signed.certificates.push(certificate)
      const index = signed.signerInfos.push(
        new pkijs.SignerInfo({
          sid: new pkijs.IssuerAndSerialNumber({
            issuer: certificate.issuer,
            serialNumber: certificate.serialNumber
          }),
          signedAttrs: new pkijs.SignedAndUnsignedAttributes({
            type: 0,
            attributes: [
              new pkijs.Attribute({
                type: new ObjectID({ name: 'contentType' }).id,
                values: [new asn1js.ObjectIdentifier({ value: new ObjectID({ name: 'data' }).id })]
              }),
              new pkijs.Attribute({
                type: new ObjectID({ name: 'signingTime' }).id,
                values: [new asn1js.UTCTime({ valueDate: new Date() })]
              }),
              new pkijs.Attribute({
                type: new ObjectID({ name: 'messageDigest' }).id,
                values: [new asn1js.OctetString({ valueHex: messageDigest })]
              })
            ]
          })
        })
      ) - 1

      if (this.digestInfo === undefined) {
        this.digestInfo = { digest: messageDigest, algorithm: hash }
      }

      await signed.sign(privateKey, index, hash, this.data, crypto)
    }

    const signedDataContent = new pkijs.ContentInfo({
      contentType: new ObjectID({ name: 'signedData' }).id,
      content: signed.toSchema(true)
    })

    return Buffer.from(signedDataContent.toSchema().toBER())
  }

  async verify (cert?: string | Buffer | PemFile, debugMode?: boolean): Promise<boolean> {
    const { pkijs, crypto } = await load()
    const signedDataContent = pkijs.ContentInfo.fromBER(toArrayBuffer(this.signature))
    const signed = new pkijs.SignedData({ schema: signedDataContent.content })
    let index = 0

    if (!isNullOrUndefined(cert)) {
      const certificate = pkijs.Certificate.fromBER(new PemFile(cert).data)

      index = signed.signerInfos.findIndex(signerInfo =>
        signerInfo.sid instanceof pkijs.IssuerAndSerialNumber &&
        certificate.issuer.isEqual(signerInfo.sid.issuer) &&
        certificate.serialNumber.isEqual(signerInfo.sid.serialNumber))

      if (index === -1) return false

      // Only trust the certificate we were given; also accepts senders that do not embed theirs.
      signed.certificates = [certificate]
    }

    let result: any
    try {
      result = await signed.verify({ signer: index, data: this.data, extendedMode: true }, crypto)
    } catch (error) {
      if (!(error instanceof pkijs.SignedDataVerifyError)) throw error
      result = error
    }

    if (result.signatureVerified === true) {
      const hashAlgorithm = crypto.getAlgorithmByOID(signed.signerInfos[index].digestAlgorithm.algorithmId, true)

      this.digestInfo = {
        digest: await crypto.digest(hashAlgorithm.name, new Uint8Array(this.data)),
        algorithm: hashAlgorithm.name
      }
    }

    return debugMode ? result : result.signatureVerified === true
  }
}

const RSA_ENCRYPTION = '1.2.840.113549.1.1.1'
const RSA_PSS = '1.2.840.113549.1.1.10'

function signingKeyAlgorithm (crypto: any, certificate: any, hash: string): Algorithm & { hash: { name: string } } {
  if (certificate.signatureAlgorithm.algorithmId === RSA_PSS) {
    return { name: 'RSA-PSS', hash: { name: hash } }
  }

  const keyAlgorithmId = certificate.subjectPublicKeyInfo.algorithm.algorithmId

  if (keyAlgorithmId === RSA_ENCRYPTION) {
    return { name: 'RSASSA-PKCS1-v1_5', hash: { name: hash } }
  }

  return { ...crypto.getAlgorithmByOID(keyAlgorithmId, true), hash: { name: hash } }
}

export interface SignMethodOptions {
  cert: string | Buffer | PemFile
  key: string | Buffer | PemFile
  algorithm: string
  addSigners?: Array<{
    cert: string | Buffer | PemFile
    key: string | Buffer | PemFile
    algorithm: string
  }>
}
