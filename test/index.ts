import { should } from 'micro-should';

// Should be first to catch obvious things
import './basic.test.ts';
import './ecdsa.test.ts';
import './modular.test.ts';
import './point.test.ts';

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
