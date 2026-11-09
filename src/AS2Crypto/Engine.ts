// pkijs and asn1js 4 are ESM-only; the package compiles to CommonJS, so load them with a real dynamic import
// (preserved by tsc under NodeNext) instead of relying on require(esm), which older Node 20 lines lack.
// The engine (Node's built-in WebCrypto) is passed to every pkijs call rather than installed with setEngine(),
// which pkijs stores in global[process.pid] where any other pkijs copy in the process can replace it.
type Pkijs = typeof import('pkijs', { with: { 'resolution-mode': 'import' } })
type Asn1js = typeof import('asn1js', { with: { 'resolution-mode': 'import' } })
type Libs = { pkijs: Pkijs, asn1js: Asn1js, crypto: InstanceType<Pkijs['CryptoEngine']> }

let libs: Promise<Libs> | undefined

export async function load (): Promise<Libs> {
  libs ??= Promise.all([import('pkijs'), import('asn1js')]).then(([pkijs, asn1js]) => ({
    pkijs,
    asn1js,
    crypto: new pkijs.CryptoEngine({ name: 'nodeWebCrypto', crypto: globalThis.crypto })
  }))

  return await libs
}

export const toArrayBuffer = (data: Uint8Array): ArrayBuffer => new Uint8Array(data).buffer
