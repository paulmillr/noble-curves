/**
 * ASN.1 DER (Distinguished Encoding Rules) helpers for ECDSA signatures.
 * Only implements the tiny subset needed for `SEQUENCE(INTEGER r, INTEGER s)`.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import {
  abignumber,
  abytes,
  asafenumber,
  astring,
  bytesToNumberBE,
  numberToHexUnpadded,
  validateObject,
  type TArg,
  type TRet,
} from '../utils.ts';

const _0n = /* @__PURE__ */ BigInt(0);

/**
 * @param m - Error message.
 * @example
 * Throw a DER-specific error when signature parsing encounters invalid bytes.
 *
 * ```ts
 * new DERErr('bad der');
 * ```
 */
export class DERErr extends Error {
  constructor(m = '') {
    super(m);
  }
}
/** DER helper namespace used by ECDSA signature parsing and encoding. */
export type IDER = {
  // asn.1 DER encoding utils
  /**
   * DER-specific error constructor.
   * @param m - Error message.
   * @returns DER-specific error instance.
   */
  Err: typeof DERErr;
  // Basic building block is TLV (Tag-Length-Value)
  /** Low-level tag-length-value helpers used by DER encoders. */
  _tlv: {
    /**
     * Encode one TLV record.
     * @param tag - ASN.1 tag byte.
     * @param data - Hex-encoded value payload.
     * @returns Encoded TLV string.
     */
    encode: (tag: number, data: string) => string;
    // v - value, l - left bytes (unparsed)
    /**
     * Decode one TLV record and return the value plus leftover bytes.
     * @param tag - Expected ASN.1 tag byte.
     * @param data - Remaining DER bytes.
     * @returns Parsed value plus leftover bytes.
     */
    decode(tag: number, data: TArg<Uint8Array>): TRet<{ v: Uint8Array; l: Uint8Array }>;
  };
  // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
  // since we always use positive integers here. It must always be empty:
  // - add zero byte if exists
  // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
  /** Positive-integer DER helpers used by ECDSA signature encoding. */
  _int: {
    /**
     * Encode one positive bigint as a DER INTEGER.
     * @param num - Positive integer to encode.
     * @returns Encoded DER INTEGER.
     */
    encode(num: bigint): string;
    /**
     * Decode one DER INTEGER into a bigint.
     * @param data - DER INTEGER bytes.
     * @returns Decoded bigint.
     */
    decode(data: TArg<Uint8Array>): bigint;
  };
  /**
   * Parse a DER signature into `{ r, s }`.
   * @param bytes - DER signature bytes.
   * @returns Parsed signature components.
   */
  toSig(bytes: TArg<Uint8Array>): { r: bigint; s: bigint };
  /**
   * Encode `{ r, s }` as a DER signature.
   * @param sig - Signature components.
   * @returns DER-encoded signature hex.
   */
  hexFromSig(sig: { r: bigint; s: bigint }): string;
};
/**
 * ASN.1 DER encoding utilities. ASN is very complex & fragile. Format:
 *
 *     [0x30 (SEQUENCE), bytelength, 0x02 (INTEGER), intLength, R, 0x02 (INTEGER), intLength, S]
 *
 * Docs: {@link https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/ | Let's Encrypt ASN.1 guide} and
 * {@link https://luca.ntop.org/Teaching/Appunti/asn1.html | Luca Deri's ASN.1 notes}.
 * @example
 * ASN.1 DER encoding utilities.
 *
 * ```ts
 * const der = DER.hexFromSig({ r: 1n, s: 2n });
 * ```
 */
export const DER: IDER = {
  // asn.1 DER encoding utils
  Err: DERErr,
  // Basic building block is TLV (Tag-Length-Value)
  _tlv: {
    encode: (tag: number, data: string): string => {
      const { Err: E } = DER;
      asafenumber(tag, 'tag');
      if (tag < 0 || tag > 255) throw new E('tlv.encode: wrong tag');
      astring(data, 'data');
      // Internal helper: callers hand this already-validated hex payload, so we only enforce
      // byte alignment here instead of re-validating every nibble.
      if (data.length & 1) throw new E('tlv.encode: unpadded data');
      const dataLen = data.length / 2;
      const len = numberToHexUnpadded(dataLen);
      if ((len.length / 2) & 0b1000_0000) throw new E('tlv.encode: long form length too big');
      // length of length with long form flag
      const lenLen = dataLen > 127 ? numberToHexUnpadded((len.length / 2) | 0b1000_0000) : '';
      const t = numberToHexUnpadded(tag);
      return t + lenLen + len + data;
    },
    // v - value, l - left bytes (unparsed)
    decode(tag: number, data: TArg<Uint8Array>): TRet<{ v: Uint8Array; l: Uint8Array }> {
      const { Err: E } = DER;
      data = abytes(data, undefined, 'DER data');
      let pos = 0;
      if (tag < 0 || tag > 255) throw new E('tlv.decode: wrong tag');
      if (data.length < 2 || data[pos++] !== tag) throw new E('tlv.decode: wrong tlv');
      const first = data[pos++];
      // First bit of first length byte is the short/long form flag.
      const isLong = !!(first & 0b1000_0000);
      let length = 0;
      if (!isLong) length = first;
      else {
        // Long form: [longFlag(1bit), lengthLength(7bit), length (BE)]
        const lenLen = first & 0b0111_1111;
        if (!lenLen) throw new E('tlv.decode(long): indefinite length not supported');
        // This would overflow u32 in JS.
        if (lenLen > 4) throw new E('tlv.decode(long): byte length is too big');
        const lengthBytes = data.subarray(pos, pos + lenLen);
        if (lengthBytes.length !== lenLen) throw new E('tlv.decode: length bytes not complete');
        if (lengthBytes[0] === 0) throw new E('tlv.decode(long): zero leftmost byte');
        for (const b of lengthBytes) length = (length << 8) | b;
        pos += lenLen;
        if (length < 128) throw new E('tlv.decode(long): not minimal encoding');
      }
      const v = data.subarray(pos, pos + length);
      if (v.length !== length) throw new E('tlv.decode: wrong value length');
      return { v, l: data.subarray(pos + length) } as TRet<{ v: Uint8Array; l: Uint8Array }>;
    },
  },
  // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
  // since we always use positive integers here. It must always be empty:
  // - add zero byte if exists
  // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
  _int: {
    encode(num: bigint): string {
      const { Err: E } = DER;
      abignumber(num);
      if (num < _0n) throw new E('integer: negative integers are not allowed');
      let hex = numberToHexUnpadded(num);
      // Pad with zero byte if negative flag is present
      if (Number.parseInt(hex[0], 16) & 0b1000) hex = '00' + hex;
      if (hex.length & 1) throw new E('unexpected DER parsing assertion: unpadded hex');
      return hex;
    },
    decode(data: TArg<Uint8Array>): bigint {
      const { Err: E } = DER;
      if (data.length < 1) throw new E('invalid signature integer: empty');
      if (data[0] & 0b1000_0000) throw new E('invalid signature integer: negative');
      // Single-byte zero `00` is the canonical DER INTEGER encoding for zero.
      if (data.length > 1 && data[0] === 0x00 && !(data[1] & 0b1000_0000))
        throw new E('invalid signature integer: unnecessary leading zero');
      return bytesToNumberBE(data);
    },
  },
  toSig(bytes: TArg<Uint8Array>): { r: bigint; s: bigint } {
    // parse DER signature
    const { Err: E, _int: int, _tlv: tlv } = DER;
    const data = abytes(bytes, undefined, 'signature');
    const { v: seqBytes, l: seqLeftBytes } = tlv.decode(0x30, data);
    if (seqLeftBytes.length) throw new E('invalid signature: left bytes after parsing');
    const { v: rBytes, l: rLeftBytes } = tlv.decode(0x02, seqBytes);
    const { v: sBytes, l: sLeftBytes } = tlv.decode(0x02, rLeftBytes);
    if (sLeftBytes.length) throw new E('invalid signature: left bytes after parsing');
    return { r: int.decode(rBytes), s: int.decode(sBytes) };
  },
  hexFromSig(sig: { r: bigint; s: bigint }): string {
    const { _tlv: tlv, _int: int } = DER;
    validateObject(sig, { r: 'bigint', s: 'bigint' }, {}, 'sig');
    const rs = tlv.encode(0x02, int.encode(sig.r));
    const ss = tlv.encode(0x02, int.encode(sig.s));
    const seq = rs + ss;
    return tlv.encode(0x30, seq);
  },
};
Object.freeze(DER._tlv);
Object.freeze(DER._int);
Object.freeze(DER);
