import { should } from 'micro-should';

import './basic.test.js';
import './rfc6979.test.js';
import './ed448.test.js';
import './ed25519.test.js';
import './secp256k1.test.js';
import './starknet/starknet.test.js';

should.run();
