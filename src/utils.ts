/**
 * Hex, bytes and number utilities.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import {
  abytes as abytes_,
  anumber as anumber_,
  bytesToHex as bytesToHex_,
  concatBytes as concatBytes_,
  hexToBytes as hexToBytes_,
  isBytes as isBytes_,
  randomBytes as randomBytes_,
} from '@noble/hashes/utils.js';
/**
 * Validates that a value is a byte array.
 * @example
 * Reject non-byte input before passing data into curve code.
 *
 * ```ts
 * abytes(new Uint8Array(1));
 * ```
 */
export const abytes: typeof abytes_ = abytes_;
/**
 * Validates that a value is a safe integer.
 * @example
 * Validate a numeric length before allocating buffers.
 *
 * ```ts
 * anumber(1);
 * ```
 */
export const anumber: typeof anumber_ = anumber_;
/**
 * Encodes bytes as lowercase hex.
 * @example
 * Serialize bytes as hex for logging or fixtures.
 *
 * ```ts
 * bytesToHex(Uint8Array.of(1, 2, 3));
 * ```
 */
export const bytesToHex: typeof bytesToHex_ = bytesToHex_;
/**
 * Concatenates byte arrays.
 * @example
 * Join domain-separated chunks into one buffer.
 *
 * ```ts
 * concatBytes(Uint8Array.of(1), Uint8Array.of(2));
 * ```
 */
export const concatBytes: typeof concatBytes_ = concatBytes_;
/**
 * Decodes lowercase or uppercase hex into bytes.
 * @example
 * Parse fixture hex into bytes before hashing.
 *
 * ```ts
 * hexToBytes('0102');
 * ```
 */
export const hexToBytes: typeof hexToBytes_ = hexToBytes_;
/**
 * Checks whether a value is a Uint8Array.
 * @example
 * Branch on byte input before decoding it.
 *
 * ```ts
 * isBytes(new Uint8Array(1));
 * ```
 */
export const isBytes: typeof isBytes_ = isBytes_;
/**
 * Reads random bytes from the platform CSPRNG.
 * @example
 * Generate a random seed for a keypair.
 *
 * ```ts
 * randomBytes(2);
 * ```
 */
export const randomBytes: typeof randomBytes_ = randomBytes_;
const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);

/** Callable hash interface with metadata and optional extendable output support. */
export type CHash = {
  /**
   * Hash one message.
   * @param message - Message bytes to hash.
   * @returns Digest bytes.
   */
  (message: Uint8Array): Uint8Array;
  /** Hash block length in bytes. */
  blockLen: number;
  /** Default output length in bytes. */
  outputLen: number;
  /**
   * Create one stateful hash or XOF instance, for example SHAKE with a custom output length.
   * @param opts - Optional extendable-output configuration:
   *   - `dkLen` (optional): Optional output length for XOF-style hashes.
   * @returns Hash instance.
   */
  create(opts?: { dkLen?: number }): any;
};
/** Plain callable hash interface. */
export type FHash = (message: Uint8Array) => Uint8Array;
/**
 * Validates that a flag is boolean.
 * @param value - Value to validate.
 * @param title - Optional field name.
 * @returns Original value.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Reject non-boolean option flags early.
 *
 * ```ts
 * abool(true);
 * ```
 */
export function abool(value: boolean, title: string = ''): boolean {
  if (typeof value !== 'boolean') {
    const prefix = title && `"${title}" `;
    throw new TypeError(prefix + 'expected boolean, got type=' + typeof value);
  }
  return value;
}

// Used in weierstrass, der
function abignumber(n: number | bigint) {
  if (typeof n === 'bigint') {
    if (!isPosBig(n)) throw new RangeError('positive bigint expected, got ' + n);
  } else anumber(n);
  return n;
}

/**
 * Validates that a value is a safe integer.
 * @param value - Integer to validate.
 * @param title - Optional field name.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Validate a window size before scalar arithmetic uses it.
 *
 * ```ts
 * asafenumber(1);
 * ```
 */
export function asafenumber(value: number, title: string = ''): void {
  if (typeof value !== 'number') {
    const prefix = title && `"${title}" `;
    throw new TypeError(prefix + 'expected number, got type=' + typeof value);
  }
  if (!Number.isSafeInteger(value)) {
    const prefix = title && `"${title}" `;
    throw new RangeError(prefix + 'expected safe integer, got ' + value);
  }
}

/**
 * Encodes a bigint into even-length big-endian hex.
 * @param num - Number to encode.
 * @returns Big-endian hex string.
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Encode a scalar into hex without a `0x` prefix.
 *
 * ```ts
 * numberToHexUnpadded(255n);
 * ```
 */
export function numberToHexUnpadded(num: number | bigint): string {
  const hex = abignumber(num).toString(16);
  return hex.length & 1 ? '0' + hex : hex;
}

/**
 * Parses a big-endian hex string into bigint.
 * @param hex - Hex string without `0x`.
 * @returns Parsed bigint value.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Parse a scalar from fixture hex.
 *
 * ```ts
 * hexToNumber('ff');
 * ```
 */
export function hexToNumber(hex: string): bigint {
  if (typeof hex !== 'string') throw new TypeError('hex string expected, got ' + typeof hex);
  return hex === '' ? _0n : BigInt('0x' + hex); // Big Endian
}

// BE: Big Endian, LE: Little Endian
/**
 * Parses big-endian bytes into bigint.
 * @param bytes - Bytes in big-endian order.
 * @returns Parsed bigint value.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Read a scalar encoded in network byte order.
 *
 * ```ts
 * bytesToNumberBE(Uint8Array.of(1, 0));
 * ```
 */
export function bytesToNumberBE(bytes: Uint8Array): bigint {
  return hexToNumber(bytesToHex_(bytes));
}
/**
 * Parses little-endian bytes into bigint.
 * @param bytes - Bytes in little-endian order.
 * @returns Parsed bigint value.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Read a scalar encoded in little-endian form.
 *
 * ```ts
 * bytesToNumberLE(Uint8Array.of(1, 0));
 * ```
 */
export function bytesToNumberLE(bytes: Uint8Array): bigint {
  return hexToNumber(bytesToHex_(copyBytes(abytes_(bytes)).reverse()));
}

/**
 * Encodes a bigint into fixed-length big-endian bytes.
 * @param n - Number to encode.
 * @param len - Output length in bytes.
 * @returns Big-endian byte array.
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Serialize a scalar into a 32-byte field element.
 *
 * ```ts
 * numberToBytesBE(255n, 2);
 * ```
 */
export function numberToBytesBE(n: number | bigint, len: number): Uint8Array {
  anumber_(len);
  n = abignumber(n);
  const res = hexToBytes_(n.toString(16).padStart(len * 2, '0'));
  if (res.length !== len) throw new RangeError('number too large');
  return res;
}
/**
 * Encodes a bigint into fixed-length little-endian bytes.
 * @param n - Number to encode.
 * @param len - Output length in bytes.
 * @returns Little-endian byte array.
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Serialize a scalar for little-endian protocols.
 *
 * ```ts
 * numberToBytesLE(255n, 2);
 * ```
 */
export function numberToBytesLE(n: number | bigint, len: number): Uint8Array {
  return numberToBytesBE(n, len).reverse();
}
// Unpadded, rarely used
/**
 * Encodes a bigint into variable-length big-endian bytes.
 * @param n - Number to encode.
 * @returns Variable-length big-endian bytes.
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Serialize a bigint without fixed-width padding.
 *
 * ```ts
 * numberToVarBytesBE(255n);
 * ```
 */
export function numberToVarBytesBE(n: number | bigint): Uint8Array {
  return hexToBytes_(numberToHexUnpadded(abignumber(n)));
}

// Compares 2 u8a-s in kinda constant time
/**
 * Compares two byte arrays in constant-ish time.
 * @param a - Left byte array.
 * @param b - Right byte array.
 * @returns `true` when bytes match.
 * @example
 * Compare two encoded points without early exit.
 *
 * ```ts
 * equalBytes(Uint8Array.of(1), Uint8Array.of(1));
 * ```
 */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Copies Uint8Array. We can't use u8a.slice(), because u8a can be Buffer,
 * and Buffer#slice creates mutable copy. Never use Buffers!
 * @param bytes - Bytes to copy.
 * @returns Detached copy.
 * @example
 * Make an isolated copy before mutating serialized bytes.
 *
 * ```ts
 * copyBytes(Uint8Array.of(1, 2, 3));
 * ```
 */
export function copyBytes(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(bytes);
}

/**
 * Decodes 7-bit ASCII string to Uint8Array, throws on non-ascii symbols
 * Should be safe to use for things expected to be ASCII.
 * Returns exact same result as `TextEncoder` for ASCII or throws.
 * @param ascii - ASCII input text.
 * @returns Encoded bytes.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Encode an ASCII domain-separation tag.
 *
 * ```ts
 * asciiToBytes('ABC');
 * ```
 */
export function asciiToBytes(ascii: string): Uint8Array {
  if (typeof ascii !== 'string') throw new TypeError('ascii string expected, got ' + typeof ascii);
  return Uint8Array.from(ascii, (c, i) => {
    const charCode = c.charCodeAt(0);
    if (c.length !== 1 || charCode > 127) {
      throw new RangeError(
        `string contains non-ASCII character "${ascii[i]}" with code ${charCode} at position ${i}`
      );
    }
    return charCode;
  });
}

// Is positive bigint
const isPosBig = (n: bigint) => typeof n === 'bigint' && _0n <= n;

/**
 * Checks whether a bigint lies inside a half-open range.
 * @param n - Candidate value.
 * @param min - Inclusive lower bound.
 * @param max - Exclusive upper bound.
 * @returns `true` when the value is inside the range.
 * @example
 * Check whether a candidate scalar fits the field order.
 *
 * ```ts
 * inRange(2n, 1n, 3n);
 * ```
 */
export function inRange(n: bigint, min: bigint, max: bigint): boolean {
  return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
}

/**
 * Asserts `min <= n < max`. NOTE: upper bound is exclusive.
 * @param title - Value label for error messages.
 * @param n - Candidate value.
 * @param min - Inclusive lower bound.
 * @param max - Exclusive upper bound.
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Assert that a bigint stays within one half-open range.
 *
 * ```ts
 * aInRange('x', 2n, 1n, 256n);
 * ```
 */
export function aInRange(title: string, n: bigint, min: bigint, max: bigint): void {
  // Why min <= n < max and not a (min < n < max) OR b (min <= n <= max)?
  // consider P=256n, min=0n, max=P
  // - a for min=0 would require -1:          `inRange('x', x, -1n, P)`
  // - b would commonly require subtraction:  `inRange('x', x, 0n, P - 1n)`
  // - our way is the cleanest:               `inRange('x', x, 0n, P)
  if (!inRange(n, min, max))
    throw new RangeError('expected valid ' + title + ': ' + min + ' <= n < ' + max + ', got ' + n);
}

// Bit operations

/**
 * Calculates amount of bits in a bigint.
 * Same as `n.toString(2).length`
 * TODO: merge with nLength in modular
 * @param n - Value to inspect.
 * @returns Bit length.
 * @example
 * Measure the bit length of a scalar before serialization.
 *
 * ```ts
 * bitLen(8n);
 * ```
 */
export function bitLen(n: bigint): number {
  let len;
  for (len = 0; n > _0n; n >>= _1n, len += 1);
  return len;
}

/**
 * Gets single bit at position.
 * NOTE: first bit position is 0 (same as arrays)
 * Same as `!!+Array.from(n.toString(2)).reverse()[pos]`
 * @param n - Source value.
 * @param pos - Bit position.
 * @returns Bit as bigint.
 * @example
 * Gets single bit at position.
 *
 * ```ts
 * bitGet(5n, 0);
 * ```
 */
export function bitGet(n: bigint, pos: number): bigint {
  return (n >> BigInt(pos)) & _1n;
}

/**
 * Sets single bit at position.
 * @param n - Source value.
 * @param pos - Bit position.
 * @param value - Whether the bit should be set.
 * @returns Updated bigint.
 * @example
 * Sets single bit at position.
 *
 * ```ts
 * bitSet(0n, 1, true);
 * ```
 */
export function bitSet(n: bigint, pos: number, value: boolean): bigint {
  return n | ((value ? _1n : _0n) << BigInt(pos));
}

/**
 * Calculate mask for N bits. Not using ** operator with bigints because of old engines.
 * Same as BigInt(`0b${Array(i).fill('1').join('')}`)
 * @param n - Number of bits.
 * @returns Bitmask value.
 * @example
 * Calculate mask for N bits.
 *
 * ```ts
 * bitMask(4);
 * ```
 */
export const bitMask = (n: number): bigint => (_1n << BigInt(n)) - _1n;

// DRBG

type Pred<T> = (v: Uint8Array) => T | undefined;
/**
 * Minimal HMAC-DRBG from NIST 800-90 for RFC6979 sigs.
 * @param hashLen - Hash output size in bytes.
 * @param qByteLen - Requested output size in bytes.
 * @param hmacFn - HMAC implementation.
 * @returns Function that will call DRBG until the predicate returns something meaningful.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Build a deterministic nonce generator for RFC6979-style signing.
 *
 * ```ts
 * import { createHmacDrbg } from '@noble/curves/utils.js';
 * import { hmac } from '@noble/hashes/hmac.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const drbg = createHmacDrbg(32, 32, (key, msg) => hmac(sha256, key, msg));
 * const seed = new Uint8Array(32);
 * drbg(seed, (bytes) => bytes);
 * ```
 */
export function createHmacDrbg<T>(
  hashLen: number,
  qByteLen: number,
  hmacFn: (key: Uint8Array, message: Uint8Array) => Uint8Array
): (seed: Uint8Array, predicate: Pred<T>) => T {
  anumber_(hashLen, 'hashLen');
  anumber_(qByteLen, 'qByteLen');
  if (typeof hmacFn !== 'function') throw new TypeError('hmacFn must be a function');
  const u8n = (len: number): Uint8Array => new Uint8Array(len); // creates Uint8Array
  const NULL = Uint8Array.of();
  const byte0 = Uint8Array.of(0x00);
  const byte1 = Uint8Array.of(0x01);
  const _maxDrbgIters = 1000;

  // Step B, Step C: set hashLen to 8*ceil(hlen/8)
  let v = u8n(hashLen); // Minimal non-full-spec HMAC-DRBG from NIST 800-90 for RFC6979 sigs.
  let k = u8n(hashLen); // Steps B and C of RFC6979 3.2: set hashLen, in our case always same
  let i = 0; // Iterations counter, will throw when over 1000
  const reset = () => {
    v.fill(1);
    k.fill(0);
    i = 0;
  };
  const h = (...msgs: Uint8Array[]) => hmacFn(k, concatBytes_(v, ...msgs)); // hmac(k)(v, ...values)
  const reseed = (seed: Uint8Array = NULL) => {
    // HMAC-DRBG reseed() function. Steps D-G
    k = h(byte0, seed); // k = hmac(k || v || 0x00 || seed)
    v = h(); // v = hmac(k || v)
    if (seed.length === 0) return;
    k = h(byte1, seed); // k = hmac(k || v || 0x01 || seed)
    v = h(); // v = hmac(k || v)
  };
  const gen = () => {
    // HMAC-DRBG generate() function
    if (i++ >= _maxDrbgIters) throw new Error('drbg: tried max amount of iterations');
    let len = 0;
    const out: Uint8Array[] = [];
    while (len < qByteLen) {
      v = h();
      const sl = v.slice();
      out.push(sl);
      len += v.length;
    }
    return concatBytes_(...out);
  };
  const genUntil = (seed: Uint8Array, pred: Pred<T>): T => {
    reset();
    reseed(seed); // Steps D-G
    let res: T | undefined = undefined; // Step H: grind until k is in [1..n-1]
    while (!(res = pred(gen()))) reseed();
    reset();
    return res;
  };
  return genUntil;
}

/**
 * Validates a plain object against required and optional field types.
 * @param object - Object to validate.
 * @param fields - Required field types.
 * @param optFields - Optional field types.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Check user options before building a curve helper.
 *
 * ```ts
 * validateObject({ flag: true }, { flag: 'boolean' });
 * ```
 */
export function validateObject(
  object: Record<string, any>,
  fields: Record<string, string> = {},
  optFields: Record<string, string> = {}
): void {
  if (Object.prototype.toString.call(object) !== '[object Object]')
    throw new TypeError('expected valid options object');
  type Item = keyof typeof object;
  function checkField(fieldName: Item, expectedType: string, isOpt: boolean) {
    const val = object[fieldName];
    if (isOpt && val === undefined) return;
    const current = typeof val;
    if (current !== expectedType || val === null)
      throw new TypeError(
        `param "${fieldName}" is invalid: expected ${expectedType}, got ${current}`
      );
  }
  const iter = (f: typeof fields, isOpt: boolean) =>
    Object.entries(f).forEach(([k, v]) => checkField(k, v, isOpt));
  iter(fields, false);
  iter(optFields, true);
}

/**
 * Throws not implemented error.
 * @returns Never returns.
 * @throws If the unfinished code path is reached. {@link Error}
 * @example
 * Surface the placeholder error from an unfinished code path.
 *
 * ```ts
 * try {
 *   notImplemented();
 * } catch {}
 * ```
 */
export const notImplemented = (): never => {
  throw new Error('not implemented');
};

/**
 * Memoizes (caches) computation result.
 * Uses WeakMap: the value is going auto-cleaned by GC after last reference is removed.
 * @param fn - Function to memoize.
 * @returns Cached wrapper.
 * @example
 * Reuse cached derived data for the same object identity.
 *
 * ```ts
 * const item = {};
 * const get = memoized((value: object) => value);
 * get(item) === get(item);
 * ```
 */
export function memoized<T extends object, R, O extends any[]>(
  fn: (arg: T, ...args: O) => R
): (arg: T, ...args: O) => R {
  const map = new WeakMap<T, R>();
  return (arg: T, ...args: O): R => {
    const val = map.get(arg);
    if (val !== undefined) return val;
    const computed = fn(arg, ...args);
    map.set(arg, computed);
    return computed;
  };
}

/** Generic keygen/getPublicKey interface shared by curve helpers. */
export interface CryptoKeys {
  /** Public byte lengths for keys and optional seeds. */
  lengths: { seed?: number; public?: number; secret?: number };
  /**
   * Generate one secret/public keypair.
   * @param seed - Optional seed bytes for deterministic key generation.
   * @returns Fresh secret/public keypair.
   */
  keygen: (seed?: Uint8Array) => { secretKey: Uint8Array; publicKey: Uint8Array };
  /**
   * Derive one public key from a secret key.
   * @param secretKey - Secret key bytes.
   * @returns Public key bytes.
   */
  getPublicKey: (secretKey: Uint8Array) => Uint8Array;
}

/** Generic interface for signatures. Has keygen, sign and verify. */
export interface Signer extends CryptoKeys {
  // Interfaces are fun. We cannot just add new fields without copying old ones.
  /** Public byte lengths for keys, signatures, and optional signing randomness. */
  lengths: {
    seed?: number;
    public?: number;
    secret?: number;
    signRand?: number;
    signature?: number;
  };
  /**
   * Sign one message.
   * @param msg - Message bytes to sign.
   * @param secretKey - Secret key bytes.
   * @returns Signature bytes.
   */
  sign: (msg: Uint8Array, secretKey: Uint8Array) => Uint8Array;
  /**
   * Verify one signature.
   * @param sig - Signature bytes.
   * @param msg - Signed message bytes.
   * @param publicKey - Public key bytes.
   * @returns `true` when the signature is valid.
   */
  verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array) => boolean;
}
