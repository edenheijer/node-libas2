// The line-based MIME parser of emailjs-mime-parser (MIT, (c) Andris Reinman / emailjs, via
// @nhs-llc/emailjs-mime-parser 2.1.0) is inlined here so the whole message is handled as latin1 ("binary") and
// every byte survives: libas2 0.5.7 decoded HTTP bodies as UTF-8 and re-encoded parsed parts as UTF-8, which
// corrupted binary (Content-Transfer-Encoding: binary) S/MIME bodies and any non-ASCII byte in a signed part.
// For ASCII/base64 traffic the result is identical. Dropped from emailjs: message/rfc822 sub-parsing,
// format=flowed, charset conversion of text parts and RFC 2231 parameter continuations, none of which AS2 uses.
import { Stream } from 'stream'
import { AS2MimeNode } from '../AS2MimeNode'

interface ParseOptions {
  headers: string[] | { [key: string]: string | string[] | undefined }
  content: Buffer | Stream | string
}

const MAXIMUM_NUMBER_OF_MIME_NODES = 999 // CWE-400 guard, as in emailjs-mime-parser

/** Splits `value; key=val; key="quoted;val"` into the value and its lowercased parameters. */
export function parseHeaderValue (header: string): { value: string, params: { [key: string]: string } } {
  const parts: string[] = []
  let current = ''
  let quoted = false

  for (let i = 0; i < header.length; i++) {
    const char = header[i]
    if (char === '\\' && quoted && i + 1 < header.length) {
      current += header[++i]
    } else if (char === '"') {
      quoted = !quoted
    } else if (char === ';' && !quoted) {
      parts.push(current)
      current = ''
    } else {
      current += char
    }
  }
  parts.push(current)

  const params: { [key: string]: string } = {}
  for (const part of parts.slice(1)) {
    const index = part.indexOf('=')
    if (index === -1) continue
    const key = part.slice(0, index).trim().toLowerCase()
    if (key) params[key] = part.slice(index + 1).trim()
  }

  return { value: parts[0].trim(), params }
}

class MimePart {
  raw = ''
  header: string[] = []
  headers: Array<{ key: string, value: string }> = []
  childNodes: MimePart[] = []
  contentTypeHeader?: string
  filename?: string
  boundary?: string
  content?: Buffer

  private state: 'HEADER' | 'BODY' = 'HEADER'
  private body = ''
  private transferEncoding = '7bit'
  private currentChild?: MimePart

  constructor (private readonly counter: { count: number }) {
    if (++counter.count > MAXIMUM_NUMBER_OF_MIME_NODES) throw new Error('Maximum number of MIME nodes exceeded!')
  }

  writeLine (line: string, terminator: string): void {
    this.raw += line + (terminator || '\n')

    if (this.state === 'HEADER') {
      if (!line) {
        this.parseHeaders()
        this.state = 'BODY'
      } else if (/^\s/.test(line) && this.header.length) {
        this.header[this.header.length - 1] += '\n' + line
      } else {
        this.header.push(line)
      }
      return
    }

    if (this.boundary === undefined) {
      this.body += line + terminator
      return
    }

    const delimiter = line.replace(/[ \t]+$/u, '') // RFC 2046 allows transport padding after a delimiter
    if (delimiter === '--' + this.boundary) {
      this.currentChild?.finalize()
      this.currentChild = new MimePart(this.counter)
      this.childNodes.push(this.currentChild)
    } else if (delimiter === '--' + this.boundary + '--') {
      this.currentChild?.finalize()
      this.currentChild = undefined
    } else {
      this.currentChild?.writeLine(line, terminator) // without a current child this is preamble/epilogue
    }
  }

  finalize (): void {
    if (this.state === 'HEADER') this.parseHeaders() // headers only, no blank line
    if (this.boundary !== undefined) {
      this.currentChild?.finalize() // tolerate a missing closing delimiter
      return
    }

    let content: Buffer
    switch (this.transferEncoding) {
      case 'base64':
        content = Buffer.from(this.body, 'base64')
        break
      case 'quoted-printable':
        content = Buffer.from(
          this.body.replace(/=(\r?\n|$)/gu, '').replace(/=([a-f0-9]{2})/giu, (_m, code: string) => String.fromCharCode(parseInt(code, 16))),
          'latin1'
        )
        break
      default:
        content = Buffer.from(this.body, 'latin1')
    }
    if (content.length > 0) this.content = content
  }

  private parseHeaders (): void {
    for (const line of this.header) {
      const index = line.indexOf(':')
      const key = (index === -1 ? line : line.slice(0, index)).trim().toLowerCase()
      const value = (index === -1 ? '' : line.slice(index + 1)).replace(/\n/gu, '').trim()
      this.headers.push({ key, value })
    }

    const first = (key: string) => this.headers.find(header => header.key === key)?.value
    this.contentTypeHeader = first('content-type')

    const contentType = parseHeaderValue(this.contentTypeHeader ?? 'text/plain')
    if (contentType.value.toLowerCase().startsWith('multipart/') && contentType.params.boundary) {
      this.boundary = contentType.params.boundary
    }

    const disposition = first('content-disposition')
    if (disposition !== undefined) this.filename = parseHeaderValue(disposition).params.filename

    this.transferEncoding = parseHeaderValue(first('content-transfer-encoding') ?? '7bit').value.toLowerCase()
  }
}

/** Splits a latin1 string into lines, reporting CRLF, LFCR, LF or CR terminators like emailjs-mime-parser. */
function parseMime (message: string): MimePart {
  const root = new MimePart({ count: 0 })
  let start = 0

  for (let i = 0; i < message.length; i++) {
    const char = message[i]
    if (char !== '\r' && char !== '\n') continue

    const pair = char + (message[i + 1] ?? '')
    const terminator = pair === '\r\n' || pair === '\n\r' ? pair : char
    root.writeLine(message.slice(start, i), terminator)
    i += terminator.length - 1
    start = i + 1
  }
  if (start < message.length) root.writeLine(message.slice(start), '')

  root.finalize()
  return root
}

function toAS2MimeNode (part: MimePart, rootNode?: AS2MimeNode, parentNode?: AS2MimeNode): AS2MimeNode {
  const node = new AS2MimeNode({
    filename: part.filename,
    contentType: part.contentTypeHeader,
    headers: part.headers,
    content: part.content,
    boundary: part.boundary,
    boundaryPrefix: false
  })

  node.rootNode = rootNode ?? node
  node.parentNode = parentNode
  node.parsed = true
  node.raw = part.raw

  for (const child of part.childNodes) {
    node.childNodes.push(toAS2MimeNode(child, node.rootNode, node))
  }

  return node
}

async function streamToBuffer (stream: Stream): Promise<Buffer> {
  const chunks: Buffer[] = []
  for await (const chunk of stream as unknown as AsyncIterable<Buffer | string>) chunks.push(Buffer.from(chunk))
  return Buffer.concat(chunks)
}

const isStream = (value: any): value is Stream => value instanceof Stream || typeof value?.on === 'function'

/** Strings are taken to be UTF-8 text (e.g. an axios responseType 'text' body); everything else as raw bytes. */
async function toLatin1 (content: Buffer | Stream | string): Promise<string> {
  if (isStream(content)) content = await streamToBuffer(content)
  return (Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8')).toString('latin1')
}

/** Class for parsing a MIME document to an AS2MimeNode tree. */
export class AS2Parser {
  /** Parse a raw MIME document, or HTTP headers plus body (as Node's `headers` object or `rawHeaders` array). */
  static async parse (content: Buffer | Stream | string | ParseOptions): Promise<AS2MimeNode> {
    let message: string

    if (typeof content === 'object' && !Buffer.isBuffer(content) && !isStream(content) && content.headers !== undefined && content.content !== undefined) {
      let headers = ''
      if (Array.isArray(content.headers)) {
        for (let i = 0; i < content.headers.length; i += 2) {
          headers += content.headers[i] + ': ' + content.headers[i + 1] + '\r\n'
        }
      } else {
        for (const [key, value] of Object.entries(content.headers)) {
          headers += key + ': ' + value + '\r\n'
        }
      }
      const body = (await toLatin1(content.content)).replace(/^[ \t\r\n\v\f]+/u, '')
      message = Buffer.from(headers, 'utf8').toString('latin1') + '\r\n' + body
    } else {
      message = await toLatin1(content as Buffer | Stream | string)
    }

    return toAS2MimeNode(parseMime(message))
  }
}
