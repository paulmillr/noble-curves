// @ts-ignore
import * as secpMod from '../src/secp256k1.ts';
export { mod } from '../src/abstract/modular.ts';
export { schnorr } from '../src/secp256k1.ts';
export { bytesToNumberBE, numberToBytesBE } from '../src/utils.ts';
const _secp = secpMod.secp256k1;
export const sigFromDER = (der) => _secp.Signature.fromBytes(der, 'der');
export const sigToDER = (sig) => _secp.Signature.fromBytes(sig).toHex('der');
export const selectHash = (secp) => secp.hash;
export const normVerifySig = (s) => _secp.Signature.fromHex(s, 'der');
export const secp = {
  ..._secp,
  __TEST: secpMod.__TEST,
  schnorr: {
    ...secpMod.schnorr,
    signAsync: async (...args) => secpMod.schnorr.sign(...args),
    verifyAsync: async (...args) => secpMod.schnorr.verify(...args),
  },
  signAsync: async (...args) => _secp.sign(...args),
  verifyAsync: async (...args) => _secp.verify(...args),
  recoverPublicKeyAsync: async (...args) => _secp.recoverPublicKey(...args),
};
