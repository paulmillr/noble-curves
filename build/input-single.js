import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/curves/abstract/utils';
export { ed25519, x25519 } from '@noble/curves/ed25519';
export const utils = { bytesToHex, hexToBytes, concatBytes, utf8ToBytes, randomBytes };
