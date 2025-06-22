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

  //console.log(basises);
  // logarr('betas', betas);
  // logarr('lambdas', lambdas);
  // logarr('basises', basises);
  // log('lambdas', lambdas.map(hex).join(', '));
  // log('betas  ', betas.map(hex).join(', '));
  // 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72n;
// /**
//  * Verify that the reduced basis generates the same lattice
//  * @param {Object} result - Result from gaussianLatticeReductionBigInt
//  * @returns {boolean} - True if verification passes
//  */
// function verifyReduction(result) {
//   const { originalBasis, reducedBasis, transformationMatrix } = result;
//   const { a, b, c, d } = transformationMatrix;

//   // Check that the transformation matrix has determinant ±1
//   const det = a * d - b * c;
//   if (det !== 1n && det !== -1n) {
//     console.error('Transformation matrix determinant is not ±1:', det.toString());
//     return false;
//   }

//   // Check that reduced basis vectors can be expressed in terms of original basis
//   const u_check = originalBasis.u.multiply(a).add(originalBasis.v.multiply(b));
//   const v_check = originalBasis.u.multiply(c).add(originalBasis.v.multiply(d));

//   if (
//     u_check.x !== reducedBasis.u.x ||
//     u_check.y !== reducedBasis.u.y ||
//     v_check.x !== reducedBasis.v.x ||
//     v_check.y !== reducedBasis.v.y
//   ) {
//     console.error('Transformation verification failed');
//     console.error('Expected u:', reducedBasis.u.toString());
//     console.error('Got u:', u_check.toString());
//     console.error('Expected v:', reducedBasis.v.toString());
//     console.error('Got v:', v_check.toString());
//     return false;
//   }

//   return true;
// }

// /**
//  * Calculate lattice properties using BigInt
//  * @param {Vector2D} u - First basis vector
//  * @param {Vector2D} v - Second basis vector
//  * @returns {Object} - Lattice properties
//  */
// function calcLatticeProps(u, v) {
//   // Area (determinant) - exact for BigInt
//   const area = u.x * v.y - u.y * v.x;
//   const absoluteArea = area < 0n ? -area : area;

//   // For angles and orthogonality, we'll provide BigInt and approximate Number versions
//   const dotProduct = u.dot(v);
//   const uNormSq = u.normSquared();
//   const vNormSq = v.normSquared();

//   return {
//     area: absoluteArea,
//     areaNumber: Number(absoluteArea), // For display
//     dotProduct: dotProduct,
//     uNormSquared: uNormSq,
//     vNormSquared: vNormSq,
//     // Approximate values for display
//     uLength: Number(u.norm()),
//     vLength: Number(v.norm()),
//     // Note: For exact orthogonality, compare dotProduct to 0n
//     isOrthogonal: dotProduct === 0n,
//   };
// }

// /**
//  * Generate a random lattice basis for testing
//  * @param {number} maxValue - Maximum absolute value for coordinates
//  * @returns {Object} - Object with two random basis vectors
//  */
// function generateRandomBasis(maxValue = 1000) {
//   const randomBigInt = (max) => {
//     const sign = Math.random() < 0.5 ? -1n : 1n;
//     const value = BigInt(Math.floor(Math.random() * max) + 1);
//     return sign * value;
//   };

//   return {
//     u: new Vector2D(randomBigInt(maxValue), randomBigInt(maxValue)),
//     v: new Vector2D(randomBigInt(maxValue), randomBigInt(maxValue)),
//   };
// }

// // Example usage and demonstration
// function demonstrateGaussianReduction() {
//   console.log('=== Gaussian Lattice Reduction with BigInt Demo ===\n');
//   // Example 3: Cryptographic-sized integers
//   const u3 = new Vector2D(
//     '115792089237316195423570985008687907852837564279074904382605163141518161494337',
//     '0'
//   );
//   const v3 = new Vector2D(
//     '37718080363155996902926221483475020450927657555482586988616620542887997980019',
//     '1'
//   );

//   console.log('Example 3 (Cryptographic-sized):');
//   console.log(`Original basis: u = ${u3}, v = ${v3}`);

//   const result3 = gaussLatticeReduction_new(u3, v3);

//   console.log(`Reduced basis: u = ${result3.reducedBasis.u}, v = ${result3.reducedBasis.v}`);
//   console.log(`Iterations: ${result3.iterations}`);
//   console.log(`Verification: ${verifyReduction(result3) ? 'PASS' : 'FAIL'}\n`);

//   // Compare properties
//   const props1 = calcLatticeProps(u3, v3);
//   const reducedProps1 = calcLatticeProps(result3.reducedBasis.u, result3.reducedBasis.v);

//   console.log('Property comparison (Example 1):');
//   console.log(`Original - Area: ${props1.area}, Is Orthogonal: ${props1.isOrthogonal}`);
//   console.log(
//     `Reduced  - Area: ${reducedProps1.area}, Is Orthogonal: ${reducedProps1.isOrthogonal}`
//   );

//   return { result3 };
// }

// // Test with random large integers
// function testRandomLargeBases(count = 5) {
//   console.log('\n=== Testing with Random Large Bases ===');

//   for (let i = 0; i < count; i++) {
//     const { u, v } = generateRandomBasis(10000);
//     console.log(`\nTest ${i + 1}:`);
//     console.log(`Basis: u = ${u}, v = ${v}`);

//     const result = gaussLatticeReduction_new(u, v);
//     const verified = verifyReduction(result);

//     console.log(`Reduced: u = ${result.reducedBasis.u}, v = ${result.reducedBasis.v}`);
//     console.log(`Iterations: ${result.iterations}, Verified: ${verified ? 'PASS' : 'FAIL'}`);
//   }
// }

// secp256k1 parameters
// const p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
// const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
// calcEndo(p, n, 0);

// assert BETA != F(1)
// assert BETA^3 == F(1)
// assert BETA^2 + BETA + 1 == 0

// assert LAMBDA != Z(1)
// assert LAMBDA^3 == Z(1)
// assert LAMBDA^2 + LAMBDA + 1 == 0
// assert Integer(LAMBDA)*G == C(BETA*G[0], G[1])
