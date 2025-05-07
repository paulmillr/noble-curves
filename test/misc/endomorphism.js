// Proper modulo function for BigInt (handles negative numbers correctly)
function mod(a, b) {
  const result = a % b;
  return result >= 0n ? result : b + result;
}

// Function to round BigInt division to nearest integer
function roundBigint(num, den) {
  if (num >= 0n) {
    return (num + den / 2n) / den;
  } else {
    return (num - den / 2n) / den;
  }
}

function gaussLatticeReduction(u, v) {
  /**
   * Apply Gauss lattice reduction to find a reduced basis for a 2D lattice.
   * This is similar to the Euclidean algorithm but for 2D vectors.
   *
   * @param {[BigInt, BigInt]} u - First basis vector
   * @param {[BigInt, BigInt]} v - Second basis vector
   * @returns {[[BigInt, BigInt], [BigInt, BigInt]]} - Reduced basis vectors
   */
  // Make copies to avoid modifying the inputs
  u = [u[0], u[1]];
  v = [v[0], v[1]];

  while (true) {
    // Ensure |u| <= |v| (swap if necessary)
    const uNormSquared = u[0] * u[0] + u[1] * u[1];
    const vNormSquared = v[0] * v[0] + v[1] * v[1];

    if (uNormSquared > vNormSquared) {
      [u, v] = [v, u];
    }

    // Calculate the dot product u·v
    const dot = u[0] * v[0] + u[1] * v[1];

    // Calculate |u|^2
    const uNormSquared2 = u[0] * u[0] + u[1] * u[1];

    // If vectors are nearly orthogonal, we're done
    // The condition 2|u·v| <= |u|^2 means the angle between u and v
    // is between 60° and 120°
    if (2n * (dot < 0n ? -dot : dot) <= uNormSquared2) {
      break;
    }

    // Calculate m = round(u·v / |u|^2)
    const m = roundBigint(dot, uNormSquared2);

    // Update v = v - m*u
    v[0] = v[0] - m * u[0];
    v[1] = v[1] - m * u[1];
  }

  return [u, v];
}

function calculateGlvBasis(n, lambda_val) {
  /**
   * Calculate a reduced basis for the GLV endomorphism on secp256k1.
   *
   * @param {BigInt} n - The order of the curve
   * @param {BigInt} lambda_val - The endomorphism value lambda
   * @returns {[[BigInt, BigInt], [BigInt, BigInt]]} - Reduced basis vectors
   */
  // Initial basis vectors for the lattice L:
  // v1 = (n, 0): This is valid because n ≡ 0 (mod n), so n + 0*lambda ≡ 0 (mod n)
  // v2 = (-lambda, 1): This is valid because -lambda + 1*lambda ≡ 0 (mod n)
  const v1 = [n, 0n];
  const v2 = [mod(-lambda_val, n), 1n];

  // Apply Gauss lattice reduction to find a reduced basis
  return gaussLatticeReduction(v1, v2);
}

function decomposeScalar(k, basis, n, lambda_val) {
  /**
   * Decompose scalar k into k1 and k2 using the GLV method.
   *
   * @param {BigInt} k - The scalar to decompose
   * @param {[[BigInt, BigInt], [BigInt, BigInt]]} basis - The reduced basis vectors
   * @param {BigInt} n - The order of the curve
   * @param {BigInt} lambda_val - The endomorphism value
   * @returns {[BigInt, BigInt]} - A tuple (k1, k2) such that k ≡ k1 + k2*lambda (mod n)
   */
  const [v1, v2] = basis;

  // Calculate the determinant of the basis
  const det = v1[0] * v2[1] - v1[1] * v2[0];

  // Use Babai's round-off algorithm:
  // Calculate continuous coordinates in the basis
  const c1 = roundBigint(k * v2[1], det);
  const c2 = roundBigint(-k * v1[1], det);

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
    d = mod(d * d, modulus)
    power >>= 1n;
  }
  return p;
}

// λ = Fn.pow(3n, (n-1n)/3n)
function findLambdaForN(n) {
  let valid = new Set();
  for (let val = 1n; val < 15n; val++) {
    const rootCandidate = powMod(val, (n - 1n)/3n, n);
    if (rootCandidate !== 1n) {
      valid.add(rootCandidate);
    }
  }
  return Array.from(valid);
}

const hex = n => '0x' + n.toString(16);
// Example usage
function main() {
  // secp256k1 parameters
  const n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
  const lambda_val = findLambdaForN(n)[1];
  console.log("Calculating reduced basis for GLV decomposition...");
  const basis = calculateGlvBasis(n, lambda_val);
  console.log(`Reduced basis vectors: v1=[${basis[0].map(hex)}], v2=[${basis[1].map(hex)}]`);

  // Test with a scalar
  const k = 2n ** 255n - 19n;  // Example scalar
  const [k1, k2] = decomposeScalar(k, basis, n, lambda_val);

  console.log(`\nScalar  ${hex(k)} decomposed as:`);
  console.log(`k1 = ${hex(k1)}`);
  console.log(`k2 = ${hex(k2)}`);

  // Verify: k ≡ k1 + k2*lambda (mod n)
  const result = mod(k1 + k2 * lambda_val, n);
  console.log(`\nVerification:`);
  console.log(`k1 + k2*lambda (mod n) = ${hex(result)}`);
  console.log(`Original k (mod n)     = ${hex(mod(k, n))}`);
  console.log(`Match: ${result === mod(k, n)}`);

  // Check the sizes of k1 and k2 compared to k
  console.log(`\nSize comparison:`);
  console.log(`|k| ≈ ${k.toString(2).length} bits`);
  console.log(`|k1| ≈ ${k1.toString(2).length} bits`);
  console.log(`|k2| ≈ ${k2.toString(2).length} bits`);
  console.log(`Theoretical target: ~${Math.floor(n.toString(2).length/2)} bits (sqrt(n))`);
}

main();