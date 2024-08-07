/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { hmac } from '@noble/hashes/hmac';
import { concatBytes, randomBytes } from '@noble/hashes/utils';
import { CHash } from './abstract/utils.js';
import { CurveType, weierstrass } from './abstract/weierstrass.js';

// connects noble-curves to noble-hashes
export function getHash(hash: CHash) {
  return {
    hash,
    hmac: (key: Uint8Array, ...msgs: Uint8Array[]) => hmac(hash, key, concatBytes(...msgs)),
    randomBytes,
  };
}
// Same API as @noble/hashes, with ability to create curve with custom hash
type CurveDef = Readonly<Omit<CurveType, 'hash' | 'hmac' | 'randomBytes'>>;
export function createCurve(curveDef: CurveDef, defHash: CHash) {
  const create = (hash: CHash) => weierstrass({ ...curveDef, ...getHash(hash) });
  return Object.freeze({ ...create(defHash), create });
}
