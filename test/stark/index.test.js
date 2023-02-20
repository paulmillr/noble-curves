import { describe, should } from 'micro-should';
import './basic.test.js';
import './stark.test.js';
import './property.test.js';
import './poseidon.test.js';

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
