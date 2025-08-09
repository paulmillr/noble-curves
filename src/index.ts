/**
 * Audited & minimal JS implementation of elliptic curve cryptography.
 * @module
 * @example
```js
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { ed25519, ed25519ph, ed25519ctx, x25519, ristretto255 } from '@noble/curves/ed25519.js';
import { ed448, ed448ph, x448, decaf448 } from '@noble/curves/ed448.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { bn254 } from '@noble/curves/bn254.js';
import { jubjub, babyjubjub, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 } from '@noble/curves/misc.js';
import * as webcrypto from '@noble/curves/webcrypto.js';

// hash-to-curve
import { secp256k1_hasher } from '@noble/curves/secp256k1.js';
import { p256_hasher, p384_hasher, p521_hasher } from '@noble/curves/nist.js';
import { ristretto255_hasher } from '@noble/curves/ed25519.js';
import { decaf448_hasher } from '@noble/curves/ed448.js';

// OPRFs
import { p256_oprf, p384_oprf, p521_oprf } from '@noble/curves/nist.js';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { decaf448_oprf } from '@noble/curves/ed448.js';

// utils
import { bytesToHex, hexToBytes, concatBytes } from '@noble/curves/abstract/utils.js';
import { Field } from '@noble/curves/abstract/modular.js';
```
 */
throw new Error('root module cannot be imported: import submodules instead. Check out README');
