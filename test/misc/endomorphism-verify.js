function calcEndo2() {
  const start = Date.now();
  log('Non-trivial cube roots of P (betas) and N (lambdas):');
  const betas = findRootsOfUnity(p);
  const lambdas = findRootsOfUnity(n);

  const basises = lambdas.map((l) => calculateGlvBasis(n, l));
  let lambdaIndex = 0;
  for (let lambda of lambdas) {
    const basis = calculateGlvBasis(n, lambda);

    log();
    log(`Calculated reduced basis vectors of lambda #${lambdaIndex} for GLV decomposition:`);
    logarr('v1', basis[0]);
    logarr('v2', basis[1]);
    const end = Date.now();
    log('Calculated endomorphism in', end - start, 'ms');

    // Test with a scalar
    const k = 2n ** 255n - 19n; // Example scalar
    const [k1, k2] = decomposeScalar(k, basis, n);

    log();
    log('Decomposing scalar s:');
    log(`s = ${hex(k)}`);
    log(`k1 = ${hex(k1)}`);
    log(`k2 = ${hex(k2)}`);

    // Verify: k ≡ k1 + k2*lambda (mod n)
    const result = mod(k1 + k2 * lambda, n);
    log(`\nVerification:`);
    log(`k1 + k2*lambda (mod n) = ${hex(result)}`);
    log(`Original k (mod n)     = ${hex(mod(k, n))}`);
    log(`Match: ${result === mod(k, n)}`);

    // Check the sizes of k1 and k2 compared to k
    log(`\nSize comparison:`);
    log(`|k| ≈ ${k.toString(2).length} bits`);
    log(`|k1| ≈ ${k1.toString(2).length} bits`);
    log(`|k2| ≈ ${k2.toString(2).length} bits`);
    log(`Theoretical target: ~${Math.floor(n.toString(2).length / 2)} bits (sqrt(n))`);
  }
  return {
    betas,
    lambdas,
    basises,
  };
}
const hex = (n) => {
  const _16 = n.toString(16);
  const abs = n < 0 ? _16.slice(1) : _16;
  const pref = n < 0 ? '-0x' : '0x';
  return pref + abs;
};
const log = (...msgs) => {
  if (config.log) console.log(...msgs);
};
const logarr = (title, arr_) => log(`${title} = [\n  ${arr_.map(hex).join(',\n  ')}\n]`);
const hex = n => n < 0 ? '-0x' + : '0x' + n.toString(16);
