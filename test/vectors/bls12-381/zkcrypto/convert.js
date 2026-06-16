// This can be done inside of tests, but ESM is broken, jest doesn't want to work with it,
// and ESM itself contaminates everything it touches

(async () => {
  const P = await import('micro-packed');
  const { readFileSync } = require('fs');

  const CompresedG1 = P.array(null, P.hex(48));
  const UncompresedG1 = P.array(null, P.hex(2 * 48));
  const CompresedG2 = P.array(null, P.hex(2 * 48));
  const UncompresedG2 = P.array(null, P.hex(4 * 48));

  const out = {
    G1_Compressed: CompresedG1.decode(readFileSync('./g1_compressed_valid_test_vectors.dat')),
    G1_Uncompressed: UncompresedG1.decode(readFileSync('./g1_uncompressed_valid_test_vectors.dat')),
    G2_Compressed: CompresedG2.decode(readFileSync('./g2_compressed_valid_test_vectors.dat')),
    G2_Uncompressed: UncompresedG2.decode(readFileSync('./g2_uncompressed_valid_test_vectors.dat')),
  };
  console.log(JSON.stringify(out));
})();
