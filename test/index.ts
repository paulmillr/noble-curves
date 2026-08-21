import { should } from '@paulmillr/jsbt/test.js';

// Should be first to catch obvious things
import './basic.test.ts';
import './ecdsa.test.ts';
import './modular.test.ts';
import './point.test.ts';

// Contains a long, indivisible 257-participant Ed448 session. Register it early so it overlaps
// the rest of the parallel suite instead of becoming the final worker tail.
import './rfc9591-frost.test.ts';

import './acvp.test.ts';
import './bls12-381.test.ts';
import './bn254.test.ts';
import './ed.test.ts';
import './ed25519.test.ts';
import './ed448.test.ts';
import './endomorphism.test.ts';
import './fft.test.ts';
import './info.test.ts';
import './misc.test.ts';
import './montgomery.test.ts';
import './nist.test.ts';
import './poseidon.test.ts';
import './rfc9380-hash-to-curve.test.ts';
import './rfc9496-ristretto-decaf.test.ts';
import './rfc9497-oprf.test.ts';
import './secp256k1.test.ts';
import './unreleased-xeddsa.ts';
import './utils.test.ts';
import './webcrypto.test.ts';

should.runWhen(import.meta.url);
