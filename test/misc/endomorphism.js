export const config = { log: true };

// Proper modulo function for BigInt (handles negative numbers correctly)
function mod(a, b) {
  const result = a % b;
  return result >= 0n ? result : b + result;
}

function bigIntSqrt(value) {
  if (value < 0n) throw new Error('Cannot compute square root of negative number');
  if (value === 0n) return 0n;
  if (value === 1n) return 1n;

  let x = value;
  let y = (x + 1n) / 2n;

  while (y < x) {
    x = y;
    y = (x + value / x) / 2n;
  }

  return x;
}

/**
 * Gaussian Lattice Reduction for 2D lattice basis vectors using BigInt arithmetic
 * Reduces a basis {u, v} to find a shorter, more orthogonal basis
 * Uses BigInt for exact integer arithmetic, crucial for cryptographic applications
 */
class Vector2D {
  constructor(x, y) {
    this.x = BigInt(x);
    this.y = BigInt(y);
  }

  // Dot product
  dot(other) {
    return this.x * other.x + this.y * other.y;
  }

  // Squared length (norm squared)
  normSquared() {
    return this.x * this.x + this.y * this.y;
  }

  // Length (norm) - returns BigInt approximation
  norm() {
    return bigIntSqrt(this.normSquared());
  }

  // Subtract another vector
  subtract(other) {
    return new Vector2D(this.x - other.x, this.y - other.y);
  }

  // Add another vector
  add(other) {
    return new Vector2D(this.x + other.x, this.y + other.y);
  }

  // Scalar multiplication
  multiply(scalar) {
    const bigScalar = BigInt(scalar);
    return new Vector2D(this.x * bigScalar, this.y * bigScalar);
  }

  // Copy vector
  copy() {
    return new Vector2D(this.x, this.y);
  }

  toString() {
    return `(${this.x.toString()}, ${this.y.toString()})`;
  }

  // Convert to regular numbers for display (with potential precision loss warning)
  toNumber() {
    const xNum = Number(this.x);
    const yNum = Number(this.y);

    // Check for precision loss
    if (
      this.x > Number.MAX_SAFE_INTEGER ||
      this.y > Number.MAX_SAFE_INTEGER ||
      this.x < Number.MIN_SAFE_INTEGER ||
      this.y < Number.MIN_SAFE_INTEGER
    ) {
      console.warn('Warning: Precision loss when converting BigInt to Number');
    }

    return { x: xNum, y: yNum };
  }
}

/**
 * Round division for BigInt (rounds to nearest integer)
 * Computes round(numerator / denominator)
 * @param {BigInt} numerator
 * @param {BigInt} denominator
 */
function roundDivisionBigInt(numerator, denominator) {
  if (denominator === 0n) throw new Error('Division by zero');

  const quotient = numerator / denominator;
  const remainder = numerator % denominator;
  const halfDenominator = denominator / 2n;

  // Handle negative numbers correctly
  if (denominator > 0n) {
    if (remainder > halfDenominator || (remainder === halfDenominator && quotient % 2n !== 0n)) {
      return quotient + 1n;
    } else if (
      remainder < -halfDenominator ||
      (remainder === -halfDenominator && quotient % 2n !== 0n)
    ) {
      return quotient - 1n;
    }
  } else {
    if (remainder < halfDenominator || (remainder === halfDenominator && quotient % 2n !== 0n)) {
      return quotient + 1n;
    } else if (
      remainder > -halfDenominator ||
      (remainder === -halfDenominator && quotient % 2n !== 0n)
    ) {
      return quotient - 1n;
    }
  }

  return quotient;
}

/**
 * Gaussian Lattice Reduction Algorithm using BigInt
 * @param {Vector2D} u - First basis vector
 * @param {Vector2D} v - Second basis vector
 * @returns {Object} - Object containing reduced basis vectors and transformation matrix
 */
function gaussLatticeReduction(u, v) {
  // Work with copies to avoid modifying original vectors
  let u1 = u.copy();
  let v1 = v.copy();

  // Keep track of the transformation matrix (BigInt)
  let transformMatrix = {
    a: 1n,
    b: 0n, // coefficients for u1 in terms of original basis
    c: 0n,
    d: 1n, // coefficients for v1 in terms of original basis
  };

  const steps = [];
  let iteration = 0;

  while (true) {
    iteration++;

    // Step 1: Ensure |u1|² <= |v1|²
    if (u1.normSquared() > v1.normSquared()) {
      // Swap u1 and v1
      [u1, v1] = [v1, u1];
      // Update transformation matrix
      [transformMatrix.a, transformMatrix.c] = [transformMatrix.c, transformMatrix.a];
      [transformMatrix.b, transformMatrix.d] = [transformMatrix.d, transformMatrix.b];

      steps.push({
        step: `Iteration ${iteration}: Swap vectors`,
        u: u1.copy(),
        v: v1.copy(),
        reason: 'Ensuring |u|² <= |v|²',
      });
    }

    // Step 2: Compute the Gram coefficient using rounded division
    const numerator = v1.dot(u1);
    const denominator = u1.normSquared();

    if (denominator === 0n) {
      throw new Error('Zero vector encountered in basis');
    }

    const mu = roundDivisionBigInt(numerator, denominator);

    if (mu === 0n) {
      // Basis is already reduced
      steps.push({
        step: `Iteration ${iteration}: Complete`,
        u: u1.copy(),
        v: v1.copy(),
        reason: 'μ = 0, basis is reduced',
      });
      break;
    }

    // Step 3: Reduce v1 by subtracting μ * u1
    const oldV1 = v1.copy();
    v1 = v1.subtract(u1.multiply(mu));

    // Update transformation matrix
    transformMatrix.c -= mu * transformMatrix.a;
    transformMatrix.d -= mu * transformMatrix.b;

    steps.push({
      step: `Iteration ${iteration}: Reduce v`,
      u: u1.copy(),
      v: v1.copy(),
      mu: mu,
      oldV: oldV1,
      reason: `v := v - ${mu.toString()} * u`,
    });

    // Check for infinite loop protection
    if (iteration > 1000) {
      console.warn('Maximum iterations reached, stopping reduction');
      break;
    }
  }

  return {
    reducedBasis: { u: u1, v: v1 },
    originalBasis: { u: u, v: v },
    transformationMatrix: transformMatrix,
    steps: steps,
    iterations: iteration,
  };
}

export function calculateScalarBound(basis) {
  const [v1, v2] = basis;
  const [v1x, v1y] = v1;
  const [v2x, v2y] = v2;
  // Calculate the squared Euclidean norms using BigInt arithmetic
  const v1NormSq = v1x * v1x + v1y * v1y;
  const v2NormSq = v2x * v2x + v2y * v2y;
  // Calculate the Euclidean norms using a BigInt square root function
  const v1Norm = bigIntSqrt(v1NormSq);
  const v2Norm = bigIntSqrt(v2NormSq);
  // The bound is 0.5 * (||v1|| + ||v2||), which is (||v1|| + ||v2||) / 2
  const bound = (v1Norm + v2Norm) / 2n;
  return bound;
}

// Run demonstration if script is executed directly
// demonstrateGaussianReductionBigInt();
// testRandomLargeBases(3);

/**
 * Calculate a reduced basis for the GLV endomorphism on secp256k1.
 *
 * @param {BigInt} n - The order of the curve
 * @param {BigInt} lambda - The endomorphism value lambda
 * @returns {[[BigInt, BigInt], [BigInt, BigInt]]} - Reduced basis vectors
 */
export function calculateGlvBasis(n, lambda) {
  // console.log({n, lambda})
  // Initial basis vectors for the lattice L:
  // v1 = (n, 0): This is valid because n ≡ 0 (mod n), so n + 0*lambda ≡ 0 (mod n)
  // v2 = (-lambda, 1): This is valid because -lambda + 1*lambda ≡ 0 (mod n)
  // const v1 = [n, 0n];
  // const v2 = [mod(-lambda, n), 1n];
  const v1 = new Vector2D(n, 0n);
  const v2 = new Vector2D(mod(-lambda, n), 1n);
  // console.log({
  //   v1, v2
  // })
  // Apply Gauss lattice reduction to find a reduced basis
  // gauss lattice reduction of initial basis vectors `(n, 0), -(λ, 0)`
  let { v, u } = gaussLatticeReduction(v1, v2).reducedBasis;
  // b) Ensure positive orientation (make sure det === n)
  const det = u.x * v.y - u.y * v.x;
  if (det < 0n) {
    // Negating one vector flips the determinant's sign.
    // Negating v is a safe choice as it preserves the length ordering.
    v = { x: -v.x, y: -v.y };
  }
  // Now the basis is fully canonical. The determinant will be `n`.
  const finalBasis = [
    [u.x, u.y],
    [v.x, v.y],
  ];
  // This check will now always pass with `det === n`
  const finalDet = finalBasis[0][0] * finalBasis[1][1] - finalBasis[0][1] * finalBasis[1][0];
  if (finalDet !== n) throw new Error(`Canonicalization failed! Final det: ${finalDet}`);
  return finalBasis;
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
  let i = 2n;
  while (true) {
    const root = powMod(i++, (fieldOrder - 1n) / 3n, fieldOrder);
    if (root === 1n) continue; // primitive root
    if (powMod(root, 3n, fieldOrder) !== 1n) continue; // check if it is real cube root
    return [root, mod(root * root, fieldOrder)];
  }
}

// Find correspoding pairs of lambda-beta. This should work for GLV stuff, but generically checking
// actual EC stuff would be better.
export function findEndoPairs(p, n) {
  const betas = findRootsOfUnity(p);
  const lambdas = findRootsOfUnity(n);
  const pairs = [
    { beta: betas[0], lambda: lambdas[1] },
    { beta: betas[1], lambda: lambdas[0] },
  ];
  return pairs;
}

export function calcEndo(p, n) {
  const res = [];
  for (const pair of findEndoPairs(p, n)) {
    const basis = calculateGlvBasis(n, pair.lambda);
    res.push({ ...pair, basis });
  }
  return res;
}

