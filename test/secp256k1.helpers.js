// @ts-ignore
import { secp256k1 as _secp } from '../esm/secp256k1.js';
export { mod } from '../esm/abstract/modular.js';
export { bytesToNumberBE, numberToBytesBE } from '../esm/abstract/utils.js';
export { schnorr } from '../esm/secp256k1.js';
export const sigFromDER = (der) => {
  return _secp.Signature.fromDER(der);
};
export const sigToDER = (sig) => sig.toDERHex();
export const selectHash = (secp) => secp.CURVE.hash;
export const normVerifySig = (s) => _secp.Signature.fromDER(s);
export const secp = _secp;
