import { should } from 'micro-should';

// Should be first to catch obvious things
import './basic.test.js';
import './ecdsa.test.js';
import './modular.test.js';
import './point.test.js';

import './acvp.test.js';
import './bls12-381.test.js';
import './bn254.test.js';
import './ed.test.js';
import './ed25519.test.js';
import './ed448.test.js';
import './endomorphism.test.js';
import './fft.test.js';
import './info.test.js';
import './misc.test.js';
import './nist.test.js';
import './poseidon.test.js';
import './rfc9380-hash-to-curve.test.js';
import './rfc9496-ristretto-decaf.test.js';
import './rfc9497-oprf.test.js';
import './secp256k1.test.js';
import './utils.test.js';
import './webcrypto.test.js';

should.runWhen(import.meta.url);
