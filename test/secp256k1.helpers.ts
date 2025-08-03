// @ts-ignore
import { secp256k1 as _secp } from '../src/secp256k1.ts';
export { mod } from '../src/abstract/modular.ts';
export { schnorr } from '../src/secp256k1.ts';
export { bytesToNumberBE, numberToBytesBE } from '../src/utils.ts';
export const sigFromDER = (der) => _secp.Signature.fromBytes(der, 'der');
export const sigToDER = (sig) => _secp.Signature.fromBytes(sig).toHex('der');
export const selectHash = (secp) => secp.hash;
export const normVerifySig = (s) => _secp.Signature.fromHex(s, 'der');
export const secp = _secp;
