import { jubjub_findGroupHash, jubjub_groupHash, jubjub as jubjubn } from './misc.ts';

/** @deprecated Use `@noble/curves/misc` module directly. */
export const jubjub: typeof jubjubn = jubjubn;
/** @deprecated Use `@noble/curves/misc` module directly. */
export const findGroupHash: typeof jubjub_findGroupHash = jubjub_findGroupHash;
/** @deprecated Use `@noble/curves/misc` module directly. */
export const groupHash: typeof jubjub_groupHash = jubjub_groupHash;
