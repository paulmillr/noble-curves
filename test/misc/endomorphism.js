// Proper modulo function for BigInt (handles negative numbers correctly)
function mod(a, b) {
  const result = a % b;
  return result >= 0n ? result : b + result;
}

// mod-div a bigint num over den, to nearest integer
function divNearest(num, den) {
  if (num >= 0n) {
    return (num + den / 2n) / den;
  } else {
    return (num - den / 2n) / den;
  }
}

/**
 * Apply Gauss lattice reduction to find a reduced basis for a 2D lattice.
 * This is similar to the Euclidean algorithm but for 2D vectors.
 *
 * @param {[BigInt, BigInt]} u - First basis vector
 * @param {[BigInt, BigInt]} v - Second basis vector
 * @returns {[[BigInt, BigInt], [BigInt, BigInt]]} - Reduced basis vectors
 */
function gaussLatticeReduction(u, v) {
  u = [u[0], u[1]]; v = [v[0], v[1]]; // copy
  while (true) {
    // Ensure |u| <= |v|, swap if necessary
    const uNormSquared = u[0] * u[0] + u[1] * u[1];
    const vNormSquared = v[0] * v[0] + v[1] * v[1];
    if (uNormSquared > vNormSquared) [u, v] = [v, u];
    const dot = u[0] * v[0] + u[1] * v[1]; // dot product u·v
    const uNormSquared2 = u[0] * u[0] + u[1] * u[1]; // |u|^2
    // If vectors are nearly orthogonal, we're done
    // 2|u·v| <= |u|^2 means: 60° < angle_between_u_and_v < 120°
    if (2n * (dot < 0n ? -dot : dot) <= uNormSquared2) break;
    const m = divNearest(dot, uNormSquared2); // m = round(u·v / |u|^2)
    v[0] = v[0] - m * u[0]; // Update v = v - m*u
    v[1] = v[1] - m * u[1];
  }
  return [u, v];
}

/**
 * Calculate a reduced basis for the GLV endomorphism on secp256k1.
 *
 * @param {BigInt} n - The order of the curve
 * @param {BigInt} lambda - The endomorphism value lambda
 * @returns {[[BigInt, BigInt], [BigInt, BigInt]]} - Reduced basis vectors
 */
function calculateGlvBasis(n, lambda) {
  // Initial basis vectors for the lattice L:
  // v1 = (n, 0): This is valid because n ≡ 0 (mod n), so n + 0*lambda ≡ 0 (mod n)
  // v2 = (-lambda, 1): This is valid because -lambda + 1*lambda ≡ 0 (mod n)
  const v1 = [n, 0n];
  const v2 = [mod(-lambda, n), 1n];
  // Apply Gauss lattice reduction to find a reduced basis
  // gauss lattice reduction of initial basis vectors `(n, 0), -(λ, 0)`
  return gaussLatticeReduction(v1, v2);
}

/**
 * Decompose scalar k into k1 and k2 using the GLV method.
 *
 * @param {BigInt} k - The scalar to decompose
 * @param {[[BigInt, BigInt], [BigInt, BigInt]]} basis - The reduced basis vectors
 * @param {BigInt} n - The order of the curve
 * @returns {[BigInt, BigInt]} - A tuple (k1, k2) such that k ≡ k1 + k2*lambda (mod n)
 */
function decomposeScalar(k, basis, n) {
  const [v1, v2] = basis;

  // Calculate the determinant of the basis
  const det = v1[0] * v2[1] - v1[1] * v2[0];

  // Use Babai's round-off algorithm:
  // Calculate continuous coordinates in the basis
  const c1 = divNearest(k * v2[1], det);
  const c2 = divNearest(-k * v1[1], det);

  // Calculate the closest lattice point to (k, 0)
  const b1 = c1 * v1[0] + c2 * v2[0];
  const b2 = c1 * v1[1] + c2 * v2[1];

  // Calculate k1 = k - b1 (mod n) and k2 = -b2 (mod n)
  const k1 = mod(k - b1, n);
  const k2 = mod(-b2, n);

  return [k1, k2];
}

function powMod(num, power, modulus) {
  if (power < 0n) throw new Error('invalid exponent, negatives unsupported');
  if (power === 0n) return 1n;
  if (power === 1n) return num;
  let p = 1n;
  let d = num;
  while (power > 0n) {
    if (power & 1n) p = mod(p * d, modulus);
    d = mod(d * d, modulus);
    power >>= 1n;
  }
  return p;
}

// There are 3 cube roots of unity (1): 1, ω, ω2.
// One of them is trivial (1).
// To calculate `cbrt(1) mod prime`:
// β is ∛1 mod p: `β = x^(p-1)/3`
// λ is ∛1 mod n: `λ = x^(n-1)/3`
function findRootsOfUnity(fieldOrder) {
  let roots;
  let i = 2n;
  while (!roots) {
    const rootCandidate = powMod(i++, (fieldOrder - 1n) / 3n, fieldOrder);
    if (rootCandidate !== 1n) {
      const root = rootCandidate;
      const root2 = mod(root * root, fieldOrder);
      roots = [root, root2]
    }
  }
  return roots;
}

const hex = (n) => {
  const _16 = n.toString(16);
  const abs = n < 0 ? _16.slice(1) : _16;
  const pref = n < 0 ? '-0x' : '0x';
  return pref + abs;
};
export const config = { log: true };
const log = (...msgs) => {
  if (config.log) console.log(...msgs);
};
const logarr = (title, arr_) => log(`${title} = [\n  ${arr_.map(hex).join(',\n  ')}\n]`);
// const hex = n => n < 0 ? '-0x' + : '0x' + n.toString(16);
// Example usage
export function calcEndo(p, n) {
  const start = Date.now();
  log('Non-trivial cube roots of P (betas) and N (lambdas):');
  const betas = findRootsOfUnity(p);
  const lambdas = findRootsOfUnity(n);
  const basises = lambdas.map(l => calculateGlvBasis(n, l));
  logarr('betas', betas);
  logarr('lambdas', lambdas);
  logarr('basises', basises);
  // log('lambdas', lambdas.map(hex).join(', '));
  // log('betas  ', betas.map(hex).join(', '));
  // 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72n;
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
    basises
  }
}

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
