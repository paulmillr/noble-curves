/**
 * Friendly wrapper over elliptic curves from built-in WebCrypto. Experimental: API may change.

# WebCrypto issues

## No way to get public keys

- Export of raw secret key is prohibited by spec:
  - https://w3c.github.io/webcrypto/#ecdsa-operations-export-key
    -> "If format is "raw":" -> "If the [[type]] internal slot of key is not "public",
       then throw an InvalidAccessError."
- Import of raw secret keys is prohibited by spec:
  - https://w3c.github.io/webcrypto/#ecdsa-operations-import-key
    -> "If format is "raw":" -> "If usages contains a value which is not "verify"
       then throw a SyntaxError."
- SPKI (Simple public-key infrastructure) is public-key-only
- PKCS8 is secret-key-only
- No way to get public key from secret key, but we convert to jwk and then create it manually, since jwk secret key is priv+pub.
- Noble supports generating keys for both sign, verify & getSharedSecret,
  but JWK key includes usage, which forces us to patch it (non-JWK is ok)
- We have import/export for 'raw', but it doesn't work in Firefox / Safari

## Point encoding

- Raw export of public points returns uncompressed points,
  but this is implementation specific and not much we can do there.
- `getSharedSecret` differs for p256, p384, p521:
  Noble returns 33-byte output (y-parity + x coordinate),
  while in WebCrypto returns 32-byte output (x coordinate)
- `getSharedSecret` identical for X25519, X448

## Availability

Node.js additionally supports ed448.
There seems no reasonable way to check for availability, other than actually calling methods.

 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */

/** Raw type */
const TYPE_RAW = 'raw';
const TYPE_JWK = 'jwk';
const TYPE_SPKI = 'spki';
const TYPE_PKCS = 'pkcs8';
/** Key serialization formats supported by the WebCrypto wrappers. */
export type WebCryptoFormat =
  | typeof TYPE_RAW
  | typeof TYPE_JWK
  | typeof TYPE_SPKI
  | typeof TYPE_PKCS;
/** WebCrypto keys can be in raw, jwk, pkcs8/spki formats. Raw is internal and fragile. */
export type WebCryptoOpts = {
  /** Preferred secret-key serialization format. */
  formatSec?: WebCryptoFormat;
  /** Preferred public-key serialization format. */
  formatPub?: WebCryptoFormat;
};
// default formats
const dfsec = TYPE_PKCS;
const dfpub = TYPE_SPKI;

function getSubtle(): any {
  const s: any = globalThis?.crypto?.subtle;
  if (typeof s === 'object' && s != null) return s;
  throw new Error('crypto.subtle must be defined');
}

function createKeygenA(randomSecretKey: any, getPublicKey: any) {
  return async function keygenA(_seed?: Uint8Array) {
    const secretKey = await randomSecretKey();
    return { secretKey, publicKey: await getPublicKey(secretKey) };
  };
}

function hexToBytesUns(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/(\w\w)/g)!, (b) => Number.parseInt(b, 16));
}

// Trying to do generics here creates hell on conversion and usage
type JsonWebKey = {
  crv?: string;
  d?: string;
  kty?: string;
  x?: string;
  y?: string;
  [key: string]: unknown;
};
type Key = JsonWebKey | Uint8Array;
type CryptoKey = Awaited<ReturnType<typeof crypto.subtle.importKey>>;
type KeyUsage = 'deriveBits' | 'deriveKey' | 'sign' | 'verify';
type Algo = string | { name: string; namedCurve: string };
type SigAlgo = string | { name: string; hash?: { name: string } };

type KeyUtils = {
  import(key: Key, format?: WebCryptoFormat): Promise<CryptoKey>;
  export(key: CryptoKey, format?: WebCryptoFormat): Promise<Key>;
  convert(key: Key, inFormat?: WebCryptoFormat, outFormat?: WebCryptoFormat): Promise<Key>;
};

function assertType(type: 'private' | 'public', key: any) {
  if (key.type !== type) throw new Error(`invalid key type, expected ${type}`);
}

function createKeyUtils(algo: Algo, derive: boolean, keyLen: number, pkcs8header: string) {
  const secUsage: KeyUsage[] = derive ? ['deriveBits'] : ['sign'];
  const pubUsage: KeyUsage[] = derive ? [] : ['verify'];
  // Return Uint8Array instead of ArrayBuffer
  const arrBufToU8 = (res: Key, format: WebCryptoFormat) =>
    format === TYPE_JWK ? res : new Uint8Array(res as unknown as ArrayBuffer);
  const pub: KeyUtils = {
    async import(key: Key, format: WebCryptoFormat): Promise<CryptoKey> {
      const keyi: CryptoKey = await getSubtle().importKey(format, key, algo, true, pubUsage);
      assertType('public', keyi);
      return keyi;
    },
    async export(key: CryptoKey, format: WebCryptoFormat): Promise<Key> {
      assertType('public', key);
      const keyi = await getSubtle().exportKey(format, key);
      return arrBufToU8(keyi, format);
    },
    async convert(key: Key, inFormat: WebCryptoFormat, outFormat: WebCryptoFormat): Promise<Key> {
      return pub.export(await pub.import(key, inFormat), outFormat);
    },
  };
  const priv: KeyUtils = {
    async import(key: Key, format: WebCryptoFormat): Promise<CryptoKey> {
      const crypto = getSubtle();
      let keyi: CryptoKey;
      if (format === TYPE_RAW) {
        // Chrome, node, bun, deno: works
        // Safari, Firefox: Data provided to an operation does not meet requirements
        // This is the best one can do. JWK can't be used: it contains public key component inside.
        const k = key as Uint8Array;
        const head = hexToBytesUns(pkcs8header);
        const all = new Uint8Array(head.length + k.length);
        all.set(head, 0);
        all.set(k, head.length);

        keyi = await crypto.importKey(TYPE_PKCS, all, algo, true, secUsage);
      } else {
        // Fix import of ECDSA keys into ECDH, other formats are ok
        if (derive && format === TYPE_JWK) key = { ...key, key_ops: secUsage };
        keyi = await crypto.importKey(format, key, algo, true, secUsage);
      }
      assertType('private', keyi);
      return keyi;
    },
    async export(key: CryptoKey, format: WebCryptoFormat): Promise<Key> {
      const crypto = getSubtle();
      assertType('private', key);
      if (format === TYPE_RAW) {
        // scure-base base64urlnopad could have been used, but we can't add more deps.
        // pkcs8 would be even more fragile
        const jwk = await crypto.exportKey(TYPE_JWK, key);
        const base64 = jwk.d.replace(/-/g, '+').replace(/_/g, '/'); // base64url
        const pad = base64.length % 4 ? '='.repeat(4 - (base64.length % 4)) : ''; // add padding
        const binary = atob(base64 + pad);
        // This is not ASCII, and not text: this is only semi-safe with atob output
        const raw = Uint8Array.from(binary, (c) => c.charCodeAt(0));
        // Pad key to key len because Bun strips leading zero for P-521 only
        const res = new Uint8Array(keyLen);
        res.set(raw, keyLen - raw.length);
        return res as Key;
      }
      const keyi = await crypto.exportKey(format, key);
      return arrBufToU8(keyi, format);
    },
    async convert(key: Key, inFormat: WebCryptoFormat, outFormat: WebCryptoFormat): Promise<Key> {
      return priv.export(await priv.import(key, inFormat), outFormat);
    },
  };
  async function getPublicKey(secretKey: Key, opts: WebCryptoOpts = {}): Promise<Key> {
    const fsec = opts.formatSec ?? dfsec;
    const fpub = opts.formatPub ?? dfpub;
    // Export to jwk, remove private scalar and then convert to format
    const jwk = (
      fsec === TYPE_JWK ? { ...secretKey } : await priv.convert(secretKey, fsec, TYPE_JWK)
    ) as JsonWebKey;
    delete jwk.d;
    jwk.key_ops = pubUsage;
    if (fpub === TYPE_JWK) return jwk;
    return pub.convert(jwk, TYPE_JWK, fpub);
  }
  async function randomSecretKey(format: WebCryptoFormat = dfsec): Promise<Key> {
    const keyPair = await getSubtle().generateKey(algo, true, secUsage);
    return priv.export(keyPair.privateKey, format);
  }
  // Key generation could be slow, so we cache result once.
  let supported: boolean | undefined;
  return {
    pub: pub as KeyUtils,
    priv: priv as KeyUtils,
    async isSupported(): Promise<boolean> {
      if (supported !== undefined) return supported;
      try {
        const crypto = getSubtle();
        const key = await crypto.generateKey(algo, true, secUsage);
        // Deno is broken and generates key for unsupported curves, but then fails on export
        await priv.export(key.privateKey, TYPE_JWK);
        // Bun fails on derive for x25519, but not x448
        if (derive) {
          await crypto.deriveBits(
            { name: typeof algo === 'string' ? algo : algo.name, public: key.publicKey },
            key.privateKey,
            8
          );
        }
        return (supported = true);
      } catch (e) {
        return (supported = false);
      }
    },
    getPublicKey,
    keygen: createKeygenA(randomSecretKey, getPublicKey),
    utils: {
      randomSecretKey,
      convertPublicKey: pub.convert as KeyUtils['convert'],
      convertSecretKey: priv.convert as KeyUtils['convert'],
    },
  };
}

function createSigner(keys: ReturnType<typeof createKeyUtils>, algo: SigAlgo): WebCryptoSigner {
  return {
    async sign(msgHash: Uint8Array, secretKey: Key, opts: WebCryptoOpts = {}): Promise<Uint8Array> {
      const key = await keys.priv.import(secretKey, opts.formatSec ?? dfsec);
      const sig = await getSubtle().sign(algo, key, msgHash);
      return new Uint8Array(sig);
    },
    async verify(
      signature: Uint8Array,
      msgHash: Uint8Array,
      publicKey: Key,
      opts: WebCryptoOpts = {}
    ): Promise<boolean> {
      const key = await keys.pub.import(publicKey, opts.formatPub ?? dfpub);
      return await getSubtle().verify(algo, key, signature, msgHash);
    },
  };
}

function createECDH(
  keys: ReturnType<typeof createKeyUtils>,
  algo: Algo,
  keyLen: number
): WebCryptoECDH {
  return {
    async getSharedSecret(
      secretKeyA: Uint8Array,
      publicKeyB: Uint8Array,
      opts: WebCryptoOpts = {}
    ): Promise<Uint8Array> {
      // if (_isCompressed !== true) throw new Error('WebCrypto only supports compressed keys');
      const secKey = await keys.priv.import(secretKeyA, opts.formatSec || dfsec);
      const pubKey = await keys.pub.import(publicKeyB, opts.formatPub || dfpub);
      const shared = await getSubtle().deriveBits(
        { name: typeof algo === 'string' ? algo : algo.name, public: pubKey },
        secKey,
        8 * keyLen
      );
      return new Uint8Array(shared);
    },
  };
}

type WebCryptoBaseCurve = {
  name: string;
  isSupported(): Promise<boolean>;
  keygen(): Promise<{ secretKey: Uint8Array; publicKey: Uint8Array }>;
  getPublicKey(secretKey: Key, opts?: WebCryptoOpts): Promise<Key>;
  utils: {
    randomSecretKey: (format?: WebCryptoFormat) => Promise<Key>;
    convertSecretKey: (
      key: Key,
      inFormat?: WebCryptoFormat,
      outFormat?: WebCryptoFormat
    ) => Promise<Key>;
    convertPublicKey: (
      key: Key,
      inFormat?: WebCryptoFormat,
      outFormat?: WebCryptoFormat
    ) => Promise<Key>;
  };
};

// Specific per-curve methods - no reason to export them; we can't "add" a new curve
/** WebCrypto signing interface shared by ECDSA and EdDSA helpers. */
export type WebCryptoSigner = {
  /**
   * Sign one message with a WebCrypto-backed private key.
   * @param message - Message bytes to sign.
   * @param secretKey - Secret key in one supported format.
   * @param opts - Optional key-format overrides. See {@link WebCryptoOpts}.
   * @returns Signature bytes.
   */
  sign(message: Uint8Array, secretKey: Key, opts?: WebCryptoOpts): Promise<Uint8Array>;
  /**
   * Verify one signature with a WebCrypto-backed public key.
   * @param signature - Signature bytes.
   * @param message - Signed message bytes.
   * @param publicKey - Public key in one supported format.
   * @param opts - Optional key-format overrides. See {@link WebCryptoOpts}.
   * @returns `true` when the signature is valid.
   */
  verify(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Key,
    opts?: WebCryptoOpts
  ): Promise<boolean>;
};
/** WebCrypto ECDH interface for shared-secret derivation. */
export type WebCryptoECDH = {
  /**
   * Derive one shared secret from a local secret key and peer public key.
   * @param secA - Local secret key in one supported format.
   * @param pubB - Peer public key in one supported format.
   * @param opts - Optional key-format overrides. See {@link WebCryptoOpts}.
   * @returns Shared secret bytes.
   */
  getSharedSecret(secA: Uint8Array, pubB: Uint8Array, opts?: WebCryptoOpts): Promise<Uint8Array>;
};
/** WebCrypto ECDSA interface with keygen, signing, and ECDH helpers. */
export type WebCryptoECDSA = WebCryptoBaseCurve & WebCryptoSigner & WebCryptoECDH;
/** WebCrypto EdDSA interface with keygen and signing helpers. */
export type WebCryptoEdDSA = WebCryptoBaseCurve & WebCryptoSigner;
/** WebCrypto Montgomery interface with keygen and ECDH helpers. */
export type WebCryptoMontgomery = WebCryptoBaseCurve & WebCryptoECDH;

function wrapECDSA(
  curve: 'P-256' | 'P-384' | 'P-521',
  hash: string,
  keyLen: number,
  pkcs8header: string
): WebCryptoECDSA {
  const ECDH_ALGO = { name: 'ECDH', namedCurve: curve };
  const keys = createKeyUtils({ name: 'ECDSA', namedCurve: curve }, false, keyLen, pkcs8header);
  const keysEcdh = createKeyUtils(ECDH_ALGO, true, keyLen, pkcs8header);
  return Object.freeze({
    name: curve,
    isSupported: keys.isSupported,
    getPublicKey: keys.getPublicKey,
    keygen: createKeygenA(keys.utils.randomSecretKey, keys.getPublicKey),
    ...createSigner(keys, { name: 'ECDSA', hash: { name: hash } }),
    ...createECDH(keysEcdh, ECDH_ALGO, keyLen),
    utils: keys.utils,
  });
}

function wrapEdDSA(
  curve: 'Ed25519' | 'Ed448',
  keyLen: number,
  pkcs8header: string
): WebCryptoEdDSA {
  const keys = createKeyUtils(curve, false, keyLen, pkcs8header);
  return Object.freeze({
    name: curve,
    isSupported: keys.isSupported,
    getPublicKey: keys.getPublicKey,
    keygen: createKeygenA(keys.utils.randomSecretKey, keys.getPublicKey),
    ...createSigner(keys, { name: curve }),
    utils: keys.utils,
  });
}

function wrapMontgomery(
  curve: 'X25519' | 'X448',
  keyLen: number,
  pkcs8header: string
): WebCryptoMontgomery {
  const keys = createKeyUtils(curve, true, keyLen, pkcs8header);
  return Object.freeze({
    name: curve,
    isSupported: keys.isSupported,
    getPublicKey: keys.getPublicKey,
    keygen: createKeygenA(keys.utils.randomSecretKey, keys.getPublicKey),
    ...createECDH(keys, curve, keyLen),
    utils: keys.utils,
  });
}

/**
 * Friendly wrapper over built-in WebCrypto NIST P-256 (secp256r1).
 * @example
 * Check support, then sign and verify once with WebCrypto P-256.
 *
 * ```ts
 * if (await p256.isSupported()) {
 *   const { secretKey, publicKey } = await p256.keygen();
 *   const msg = new TextEncoder().encode('hello noble');
 *   const sig = await p256.sign(msg, secretKey);
 *   const isValid = await p256.verify(sig, msg, publicKey);
 * }
 * ```
 */
export const p256: WebCryptoECDSA = /* @__PURE__ */ wrapECDSA(
  'P-256',
  'SHA-256',
  32,
  '3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420'
);

/**
 * Friendly wrapper over built-in WebCrypto NIST P-384 (secp384r1).
 * @example
 * Check support, then sign and verify once with WebCrypto P-384.
 *
 * ```ts
 * if (await p384.isSupported()) {
 *   const { secretKey, publicKey } = await p384.keygen();
 *   const msg = new TextEncoder().encode('hello noble');
 *   const sig = await p384.sign(msg, secretKey);
 *   const isValid = await p384.verify(sig, msg, publicKey);
 * }
 * ```
 */
export const p384: WebCryptoECDSA = /* @__PURE__ */ wrapECDSA(
  'P-384',
  'SHA-384',
  48,
  '304e020100301006072a8648ce3d020106052b81040022043730350201010430'
);

/**
 * Friendly wrapper over built-in WebCrypto NIST P-521 (secp521r1).
 * @example
 * Check support, then sign and verify once with WebCrypto P-521.
 *
 * ```ts
 * if (await p521.isSupported()) {
 *   const { secretKey, publicKey } = await p521.keygen();
 *   const msg = new TextEncoder().encode('hello noble');
 *   const sig = await p521.sign(msg, secretKey);
 *   const isValid = await p521.verify(sig, msg, publicKey);
 * }
 * ```
 */
export const p521: WebCryptoECDSA = /* @__PURE__ */ wrapECDSA(
  'P-521',
  'SHA-512',
  66,
  '3060020100301006072a8648ce3d020106052b81040023044930470201010442'
);

/**
 * Friendly wrapper over built-in WebCrypto ed25519.
 * @example
 * Check support, then sign and verify once with WebCrypto Ed25519.
 *
 * ```ts
 * if (await ed25519.isSupported()) {
 *   const { secretKey, publicKey } = await ed25519.keygen();
 *   const msg = new TextEncoder().encode('hello noble');
 *   const sig = await ed25519.sign(msg, secretKey);
 *   const isValid = await ed25519.verify(sig, msg, publicKey);
 * }
 * ```
 */
export const ed25519: WebCryptoEdDSA = /* @__PURE__ */ wrapEdDSA(
  'Ed25519',
  32,
  '302e020100300506032b657004220420'
);

/**
 * Friendly wrapper over built-in WebCrypto ed448.
 * @example
 * Check support, then sign and verify once with WebCrypto Ed448.
 *
 * ```ts
 * if (await ed448.isSupported()) {
 *   const { secretKey, publicKey } = await ed448.keygen();
 *   const msg = new TextEncoder().encode('hello noble');
 *   const sig = await ed448.sign(msg, secretKey);
 *   const isValid = await ed448.verify(sig, msg, publicKey);
 * }
 * ```
 */
export const ed448: WebCryptoEdDSA = /* @__PURE__ */ wrapEdDSA(
  'Ed448',
  57,
  '3047020100300506032b6571043b0439'
);

/**
 * Friendly wrapper over built-in WebCrypto x25519 (ECDH over Curve25519).
 * @example
 * Check support, then derive one shared secret with WebCrypto X25519.
 *
 * ```ts
 * if (await x25519.isSupported()) {
 *   const alice = await x25519.keygen();
 *   const bob = await x25519.keygen();
 *   const shared = await x25519.getSharedSecret(alice.secretKey, bob.publicKey);
 * }
 * ```
 */
export const x25519: WebCryptoMontgomery = /* @__PURE__ */ wrapMontgomery(
  'X25519',
  32,
  '302e020100300506032b656e04220420'
);

/**
 * Friendly wrapper over built-in WebCrypto x448 (ECDH over Curve448).
 * @example
 * Check support, then derive one shared secret with WebCrypto X448.
 *
 * ```ts
 * if (await x448.isSupported()) {
 *   const alice = await x448.keygen();
 *   const bob = await x448.keygen();
 *   const shared = await x448.getSharedSecret(alice.secretKey, bob.publicKey);
 * }
 * ```
 */
export const x448: WebCryptoMontgomery = /* @__PURE__ */ wrapMontgomery(
  'X448',
  56,
  '3046020100300506032b656f043a0438'
);
