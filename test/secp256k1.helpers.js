// @ts-ignore
import { secp256k1 as _secp } from '../esm/secp256k1.js';
export { mod } from '../esm/abstract/modular.js';
export { bytesToNumberBE, numberToBytesBE } from '../esm/abstract/utils.js';
export { schnorr } from '../esm/secp256k1.js';
export const sigFromDER = (der) => _secp.Signature.fromHex(der, 'der');
export const sigToDER = (sig) => sig.toHex('der');
export const selectHash = (secp) => secp.CURVE.hash;
export const normVerifySig = (s) => _secp.Signature.fromHex(s, 'der');
export const secp = _secp;
