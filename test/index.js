import { should } from 'micro-should';

// Should be first to catch obvious things
import './basic.test.js';
import './bls12-381.test.js';
import './bn254.test.js';
import './ed25519-addons.test.js';
import './ed25519.test.js';
import './ed448-addons.test.js';
import './ed448.test.js';
import './hash-to-curve.test.js';
import './jubjub.test.js';
import './nist.test.js';
import './poseidon.test.js';
import './secp256k1-schnorr.test.js';
import './secp256k1.test.js';
import './utils.test.js';

should.runWhen(import.meta.url);
