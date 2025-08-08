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
import { concatBytes, hexToBytes } from './utils.ts';

function getWebcryptoSubtle(): any {
  const subtle: any = globalThis?.crypto?.subtle;
  if (typeof subtle === 'object' && subtle != null) return subtle;
  throw new Error('crypto.subtle must be defined');
}
type Format = 'raw' | 'jwk' | 'spki' | 'pkcs8';
type WebCryptoOptsSec = { formatSec?: Format };
type WebCryptoOptsPub = { formatPub?: Format };
export type WebCryptoOptsSecPub = {
  formatSec?: Format;
  formatPub?: Format;
};
const dfsec = 'pkcs8'; // default format sec
const dfpub = 'spki'; // default format pub

function createKeygen(randomSecretKey: any, getPublicKey: any) {
  return async function keygen(_seed?: Uint8Array) {
    const secretKey = await randomSecretKey();
    return { secretKey, publicKey: await getPublicKey(secretKey) };
  };
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
  import(key: Key, format?: Format): Promise<CryptoKey>;
  export(key: CryptoKey, format?: Format): Promise<Key>;
  convert(key: Key, inFormat?: Format, outFormat?: Format): Promise<Key>;
};

function assertType(type: 'private' | 'public', key: any) {
  if (key.type !== type) throw new Error(`invalid key type, expected ${type}`);
}

function createKeyUtils(algo: Algo, derive: boolean, keyLen: number, pkcs8header: string) {
  const secUsage: KeyUsage[] = derive ? ['deriveBits'] : ['sign'];
  const pubUsage: KeyUsage[] = derive ? [] : ['verify'];
  // Return Uint8Array instead of ArrayBuffer
  const arrBufToU8 = (res: Key, format: Format) =>
    format === 'jwk' ? res : new Uint8Array(res as ArrayBuffer);
  const pub: KeyUtils = {
    async import(key: Key, format: Format): Promise<CryptoKey> {
      const crypto = getWebcryptoSubtle();
      const keyi: CryptoKey = await crypto.importKey(format, key, algo, true, pubUsage);
      assertType('public', keyi);
      return keyi;
    },
    async export(key: CryptoKey, format: Format): Promise<Key> {
      assertType('public', key);
      const crypto = getWebcryptoSubtle();
      const keyi = await crypto.exportKey(format, key);
      return arrBufToU8(keyi, format);
    },
    async convert(key: Key, inFormat: Format, outFormat: Format): Promise<Key> {
      return pub.export(await pub.import(key, inFormat), outFormat);
    },
  };
  const priv: KeyUtils = {
    async import(key: Key, format: Format): Promise<CryptoKey> {
      const crypto = getWebcryptoSubtle();
      let keyi: CryptoKey;
      if (format === 'raw') {
        // Chrome, node, bun, deno: works
        // Safari, Firefox: Data provided to an operation does not meet requirements
        // This is the best one can do. JWK can't be used: it contains public key component inside.
        keyi = await crypto.importKey(
          'pkcs8',
          concatBytes(hexToBytes(pkcs8header), key as Uint8Array),
          algo,
          true,
          secUsage
        );
      } else {
        // Fix import of ECDSA keys into ECDH, other formats are ok
        if (derive && format === 'jwk') key = { ...key, key_ops: secUsage };
        keyi = await crypto.importKey(format, key, algo, true, secUsage);
      }
      assertType('private', keyi);
      return keyi;
    },
    async export(key: CryptoKey, format: Format): Promise<Key> {
      const crypto = getWebcryptoSubtle();
      assertType('private', key);
      if (format === 'raw') {
        // scure-base base64urlnopad could have been used, but we can't add more deps.
        // pkcs8 would be even more fragile
        const jwk = await crypto.exportKey('jwk', key);
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
    async convert(key: Key, inFormat: Format, outFormat: Format): Promise<Key> {
      return priv.export(await priv.import(key, inFormat), outFormat);
    },
  };
  async function getPublicKey(secretKey: Key, opts: WebCryptoOptsSecPub = {}): Promise<Key> {
    const fsec = opts.formatSec ?? dfsec;
    const fpub = opts.formatPub ?? dfpub;
    // Export to jwk, remove private scalar and then convert to format
    const jwk = (
      fsec === 'jwk' ? { ...secretKey } : await priv.convert(secretKey, fsec, 'jwk')
    ) as JsonWebKey;
    delete jwk.d;
    jwk.key_ops = pubUsage;
    if (fpub === 'jwk') return jwk;
    return pub.convert(jwk, 'jwk', fpub);
  }
  async function randomSecretKey(format: Format = dfsec): Promise<Key> {
    const crypto = getWebcryptoSubtle();
    const keyPair = await crypto.generateKey(algo, true, secUsage);
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
        const crypto = getWebcryptoSubtle();
        const key = await crypto.generateKey(algo, true, secUsage);
        // Deno is broken and generates key for unsupported curves, but then fails on export
        await priv.export(key.privateKey, 'jwk');
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
    keygen: createKeygen(randomSecretKey, getPublicKey),
    utils: {
      randomSecretKey,
      convertPublicKey: pub.convert as KeyUtils['convert'],
      convertSecretKey: priv.convert as KeyUtils['convert'],
    },
  };
}

function createSigner(keys: ReturnType<typeof createKeyUtils>, algo: SigAlgo): WebCryptoSigner {
  return {
    async sign(
      msgHash: Uint8Array,
      secretKey: Key,
      opts: WebCryptoOptsSec = {}
    ): Promise<Uint8Array> {
      const crypto = getWebcryptoSubtle();
      const key = await keys.priv.import(secretKey, opts.formatSec ?? dfsec);
      const sig = await crypto.sign(algo, key, msgHash);
      return new Uint8Array(sig);
    },
    async verify(
      signature: Uint8Array,
      msgHash: Uint8Array,
      publicKey: Key,
      opts: WebCryptoOptsPub = {}
    ): Promise<boolean> {
      const crypto = getWebcryptoSubtle();
      const key = await keys.pub.import(publicKey, opts.formatPub ?? dfpub);
      return await crypto.verify(algo, key, signature, msgHash);
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
      opts: WebCryptoOptsSecPub = {}
    ): Promise<Uint8Array> {
      // if (_isCompressed !== true) throw new Error('WebCrypto only supports compressed keys');
      const crypto = getWebcryptoSubtle();
      const secKey = await keys.priv.import(secretKeyA, opts.formatSec || dfsec);
      const pubKey = await keys.pub.import(publicKeyB, opts.formatPub || dfpub);
      const shared = await crypto.deriveBits(
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
  getPublicKey(secretKey: Key, opts?: WebCryptoOptsSecPub): Promise<Key>;
  utils: {
    randomSecretKey: (format?: Format) => Promise<Key>;
    convertSecretKey: (key: Key, inFormat?: Format, outFormat?: Format) => Promise<Key>;
    convertPublicKey: (key: Key, inFormat?: Format, outFormat?: Format) => Promise<Key>;
  };
};

// Specific per-curve methods - no reason to export them; we can't "add" a new curve
export type WebCryptoSigner = {
  sign(message: Uint8Array, secretKey: Key, opts?: WebCryptoOptsSec): Promise<Uint8Array>;
  verify(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Key,
    opts?: WebCryptoOptsPub
  ): Promise<boolean>;
};
export type WebCryptoECDH = {
  getSharedSecret(
    secA: Uint8Array,
    pubB: Uint8Array,
    opts?: WebCryptoOptsSecPub
  ): Promise<Uint8Array>;
};
export type WebCryptoECDSA = WebCryptoBaseCurve & WebCryptoSigner & WebCryptoECDH;
export type WebCryptoEdDSA = WebCryptoBaseCurve & WebCryptoSigner;
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
    keygen: createKeygen(keys.utils.randomSecretKey, keys.getPublicKey),
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
    keygen: createKeygen(keys.utils.randomSecretKey, keys.getPublicKey),
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
    keygen: createKeygen(keys.utils.randomSecretKey, keys.getPublicKey),
    ...createECDH(keys, curve, keyLen),
    utils: keys.utils,
  });
}

export const p256: WebCryptoECDSA = /* @__PURE__ */ wrapECDSA(
  'P-256',
  'SHA-256',
  32,
  '3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420'
);
export const p384: WebCryptoECDSA = /* @__PURE__ */ wrapECDSA(
  'P-384',
  'SHA-384',
  48,
  '304e020100301006072a8648ce3d020106052b81040022043730350201010430'
);
export const p521: WebCryptoECDSA = /* @__PURE__ */ wrapECDSA(
  'P-521',
  'SHA-512',
  66,
  '3060020100301006072a8648ce3d020106052b81040023044930470201010442'
);

export const ed25519: WebCryptoEdDSA = /* @__PURE__ */ wrapEdDSA(
  'Ed25519',
  32,
  '302e020100300506032b657004220420'
);
export const ed448: WebCryptoEdDSA = /* @__PURE__ */ wrapEdDSA(
  'Ed448',
  57,
  '3047020100300506032b6571043b0439'
);

export const x25519: WebCryptoMontgomery = /* @__PURE__ */ wrapMontgomery(
  'X25519',
  32,
  '302e020100300506032b656e04220420'
);
export const x448: WebCryptoMontgomery = /* @__PURE__ */ wrapMontgomery(
  'X448',
  56,
  '3046020100300506032b656f043a0438'
);
