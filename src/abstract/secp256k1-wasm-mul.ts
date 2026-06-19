import createSecp256k1Wasm from './secp256k1-wasm.ts';

type K1Point<T> = Readonly<{ X: T; Y: T; Z: T }>;

const BYTES = 32;
const POINT_BYTES = BYTES * 3;

type K1Wasm = {
  mulBaseWnaf: () => void;
  mulLadder: () => void;
  segments: {
    scalar: Uint8Array;
    point: Uint8Array;
    result: Uint8Array;
    baseReady: Uint8Array;
  };
};

const wasm = /* @__PURE__ */ (() => createSecp256k1Wasm() as K1Wasm)();

function isCoord(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array && value.length === BYTES;
}

function setScalarLE(out: Uint8Array, scalar: bigint): void {
  for (let i = 0; i < BYTES; i++) {
    out[i] = Number(scalar & BigInt(0xff));
    scalar >>= BigInt(8);
  }
}

function setPoint(point: K1Point<unknown>): boolean {
  const { X, Y, Z } = point;
  if (!isCoord(X) || !isCoord(Y) || !isCoord(Z)) return false;
  const out = wasm.segments.point;
  out.set(X, 0);
  out.set(Y, BYTES);
  out.set(Z, BYTES * 2);
  return true;
}

function copyResult<T>(): [T, T, T] {
  const result = wasm.segments.result;
  return [
    new Uint8Array(result.subarray(0, BYTES)) as T,
    new Uint8Array(result.subarray(BYTES, BYTES * 2)) as T,
    new Uint8Array(result.subarray(BYTES * 2, POINT_BYTES)) as T,
  ];
}

export function secp256k1WasmMultiply<T>(
  point: K1Point<T>,
  scalar: bigint,
  opts: Readonly<{ unsafe: boolean; isBase: boolean }>
): [T, T, T] | undefined {
  const { segments } = wasm;
  segments.scalar.fill(0);
  setScalarLE(segments.scalar, scalar);
  if (opts.isBase) {
    if (segments.baseReady[0] === 0 && !setPoint(point)) return undefined;
    wasm.mulBaseWnaf();
  } else {
    if (!opts.unsafe || !setPoint(point)) return undefined;
    wasm.mulLadder();
  }
  return copyResult<T>();
}
