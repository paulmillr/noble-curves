// @ts-ignore
export { secp256k1 as secp } from '../lib/esm/secp256k1.js';
import { secp256k1 as _secp } from '../lib/esm/secp256k1.js';
export { bytesToNumberBE, numberToBytesBE } from '../lib/esm/abstract/utils.js';
export { mod } from '../lib/esm/abstract/modular.js';
export const sigFromDER = (der) => {
  return _secp.Signature.fromDER(der);
};
export const sigToDER = (sig) => sig.toDERHex();
export const selectHash = (secp) => secp.CURVE.hash;
export const normVerifySig = (s) => _secp.Signature.fromDER(s);
// export const bytesToNumberBE = secp256k1.utils.bytesToNumberBE;
// export const numberToBytesBE = secp256k1.utils.numberToBytesBE;
// export const mod = mod_;
