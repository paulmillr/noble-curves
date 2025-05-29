/**
 * NIST secp521r1 aka p521.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { type H2CMethod } from './abstract/hash-to-curve.ts';
import { p521_hasher, p521 as p521n } from './nist.ts';
export const p521: typeof p521n = p521n;
export const secp521r1: typeof p521n = p521n;
export const hashToCurve: H2CMethod<bigint> = /* @__PURE__ */ (() => p521_hasher.hashToCurve)();
export const encodeToCurve: H2CMethod<bigint> = /* @__PURE__ */ (() => p521_hasher.encodeToCurve)();
