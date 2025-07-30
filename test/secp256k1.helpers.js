// @ts-ignore
import { secp256k1 as _secp } from '../secp256k1.js';
export { mod } from '../abstract/modular.js';
export { schnorr } from '../secp256k1.js';
export { bytesToNumberBE, numberToBytesBE } from '../utils.js';
export const sigFromDER = (der) => _secp.Signature.fromBytes(der, 'der');
export const sigToDER = (sig) => _secp.Signature.fromBytes(sig).toHex('der');
export const selectHash = (secp) => secp.hash;
export const normVerifySig = (s) => _secp.Signature.fromHex(s, 'der');
export const secp = _secp;
