# libas2 (WG Den Heijer fork)

> **About this fork.** This fork of [ahuggins-nhs/node-libas2](https://github.com/ahuggins-nhs/node-libas2), by Aaron Huggins, is maintained for W.G. den Heijer & Zn. B.V.'s own use. It is **not published to npm** and comes with **no support and no compatibility guarantees**. Releases are tagged here, and the built package is attached to each release as a tarball.
>
> It branches from upstream **0.5.7** (commit `08b6835`) and keeps that version's API and the package name `libas2`. Changes:
> - Dependencies: [pkijs](https://github.com/PeculiarVentures/PKI.js)/asn1js **4** instead of 2, and Node's built-in WebCrypto instead of `@peculiar/webcrypto`. nodemailer **10** replaces 6.x; a test checks that it serializes AS2 MIME byte-for-byte like 6.10.1. The `@nhs-llc/emailjs-mime-parser` dependency is inlined. Requires Node 20+.
> - Signing works without the `@peculiar/webcrypto` `importKey` monkeypatch that 0.5.7 needed (the key is imported as RSASSA-PKCS1-v1_5).
> - Inbound PKCS#1 v1.5 key transport (`rsaEncryption`, what most AS2 products send) decrypts on current Node. A bad block always yields a random key, per RFC 3218, never an error. The decryption path depends on Node's OpenSSL (`hasNativeImplicitRejection()` reports which one is used):
>   - **OpenSSL 3.2+ (e.g. Node 24):** Node's own `privateDecrypt` with `RSA_PKCS1_PADDING` and OpenSSL's implicit rejection. This is the preferred path.
>   - **OpenSSL 3.0 (e.g. Node 20/22):** Node refuses that call since CVE-2023-46809, so the padding is removed in JavaScript in a single branch-free pass, with the fallback key drawn up front and the result chosen by mask. `scripts/pkcs1-timing.ts` measures valid vs invalid blocks. On Node 22.14 the median gap went from about 2.5–3 µs in v0.5.8-wgdh.1 to 0.3–0.6 µs, of which 0.1–0.3 µs is already in OpenSSL's raw RSA operation. JavaScript cannot guarantee constant time, so prefer a Node with OpenSSL 3.2+, or have partners use RSA-OAEP key transport, which avoids this path entirely.
> - Signatures are verified against the certificate you pass in, not a certificate embedded in the message under the same issuer and serial.
> - Signed MDNs and CRLF-terminated 7bit parts are signed over the RFC 1847 byte range. 0.5.7's signed MDNs failed OpenSSL and 0.5.7's own verifier; MDNs and messages signed by 0.5.7 still verify here. Outgoing MDNs say `micalg=<algorithm>` instead of `micalg=undefined`.
> - The parser keeps every byte, so `Content-Transfer-Encoding: binary` and non-ASCII signed parts no longer get corrupted by a UTF-8 round trip.
> - Build with `tsc`, test with vitest: upstream's suites still pass, and `test/fork.test.ts` adds OpenSSL interop and live interop against the original `libas2@0.5.7`.
>
> The original README follows.

## libas2

A pure Javascript/Typescript implementation of the AS2 protocol. This project assumes that it fully implements Applicability Statement 2 (AS2) version 1.0 per RFC 4130. Best effort has been made to achieve tests which cover the different aspects of the RFC, but **this is not a certified library**. The project does not have access to Drummond certification, which is considered to be the standards body in certifying compatibility with AS2, so good sense should be used when using this library as the AS2 layer in an application.

[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://github.com/standard/eslint-config-standard-with-typescript)
[![codecov](https://codecov.io/gh/ahuggins-nhs/node-libas2/branch/master/graph/badge.svg)](https://codecov.io/gh/ahuggins-nhs/node-libas2)
![GitHub last commit](https://img.shields.io/github/last-commit/ahuggins-nhs/node-libas2)
![GitHub contributors](https://img.shields.io/github/contributors/ahuggins-nhs/node-libas2)
![npm collaborators](https://img.shields.io/npm/collaborators/libas2)<br />
![GitHub top language](https://img.shields.io/github/languages/top/ahuggins-nhs/node-libas2)
![npm bundle size](https://img.shields.io/bundlephobia/min/libas2)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/ahuggins-nhs/node-libas2)
![npm](https://img.shields.io/npm/dw/libas2)
![NPM](https://img.shields.io/npm/l/libas2)<br />
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=ahuggins-nhs_node-libas2&metric=alert_status)](https://sonarcloud.io/dashboard?id=ahuggins-nhs_node-libas2)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=ahuggins-nhs_node-libas2&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=ahuggins-nhs_node-libas2)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=ahuggins-nhs_node-libas2&metric=security_rating)](https://sonarcloud.io/dashboard?id=ahuggins-nhs_node-libas2)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=ahuggins-nhs_node-libas2&metric=ncloc)](https://sonarcloud.io/dashboard?id=ahuggins-nhs_node-libas2)

## **WARNING**

**BETA SOFTWARE**

This library is not quite yet ready for production use. The API is still in flux, but nearly finished. This will be settled soon to allow for a production version 1.0.0 release. Documentation of the API is complete and work is being done to keep the documentation up-to-date.

## Usage

Install it from the [npm repository](https://www.npmjs.com/package/libas2):

```console
npm install --save libas2
```

Then require it in your project:

```js
const { AS2Composer } = require('libas2')
```

The TypeScript code is compiled to JavaScript and distributed via NPM. If you wish to use the TypeScript code directly you can [download the zip](https://github.com/ahuggins-nhs/libas2/releases/latest) and unpack it locally.

Then import it in your project:

```typescript
import { AS2Composer } from './libas2/core.ts'
```

## Features

- Compose AS2 messages to send, including signing and encrypting
- Parse received AS2 messages, including decrypting and verifying
- Generate and consume Message Disposition Notifications; includes convenience methods for incoming and outgoing dispositions
- Complete support for AS2 protocol 1.0 [per RFC 4130](https://tools.ietf.org/html/rfc4130); see roadmap
- Rich cryptography support based on [PKIjs](https://github.com/PeculiarVentures/PKI.js)
- Rich MIME support based on [Nodemailer](https://github.com/nodemailer/nodemailer) and [Emailjs](https://github.com/emailjs/emailjs-mime-parser)

## Roadmap

- Finish README for libas2 1.x release
- Write implementation of CMS compression to support AS2 version 1.1 (see rfc4130 section 6.1)
- Support versions of AS2 greater than 1.1

## API

See the [API document](/docs/API.md) for complete information.

## Contribute

> **Help Wanted:** Any experience writing test suites for AS2 would be welcome.

Contributions, especially from those familiar with the AS2 protocol, are welcome. If you can improve the code, please fork it and fire off a pull request.

This project uses Standard JS, specifically through `prettier-standard`; please format pull requests before submitting to avoid having your contributions incorrectly attributed in the pull request by a code formatting.
