import { pippenger as _pippenger, precomputeMSMUnsafe as _precomputeMSMUnsafe } from '../src/abstract/curve.ts';
import { bls12_381 } from '../src/bls12-381.ts';
import { ed25519, ed25519ctx, ed25519ph, ristretto255 } from '../src/ed25519.ts';
import { decaf448, ed448, ed448ph } from '../src/ed448.ts';
import { brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, jubjub } from '../src/misc.ts';
import { p256 as secp256r1, p384 as secp384r1, p521 as secp521r1 } from '../src/nist.ts';
import { secp256k1 } from '../src/secp256k1.ts';
import { miscCurves, secp192r1, secp224r1 } from './_more-curves.helpers.ts';
import {
  bytesToHex as hex,
  hexToBytes,
  invert,
  mod,
} from './utils.helpers.ts';

// prettier-ignore
export const CURVES = {
  secp192r1,
  secp224r1,
  secp256r1,
  secp384r1,
  secp521r1,
  secp256k1,
  ed25519,
  ed25519ctx,
  ed25519ph,
  ed448,
  ed448ph,
  jubjub,
  brainpoolP256r1,
  brainpoolP384r1,
  brainpoolP512r1,
  bls12_381_G1: bls12_381.G1,
  bls12_381_G2: bls12_381.G2,
  // Requires fromHex/toHex
  // bn254_G1: bn254.G1,
  // bn254_G2: bn254.G2,
  ristretto: { ...ed25519, Point: ristretto255.Point },
  decaf: { ...ed448, Point: decaf448.Point },
};
Object.assign(CURVES, miscCurves);

export function getOtherCurve(currCurveName) {
  return currCurveName === 'secp256k1' ? secp256r1 : secp256k1;
}

export const pippenger = _pippenger;
export const precomputeMSMUnsafe = _precomputeMSMUnsafe;
export { hex, hexToBytes, invert, mod };
