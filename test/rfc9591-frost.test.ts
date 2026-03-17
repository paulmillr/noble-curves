import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import type {
  DKG_Round1,
  DKG_Round2,
  DKG_Secret,
  FROST,
  FrostPublic,
  FrostSecret,
  Key,
  NonceCommitments,
  Nonces,
} from '../src/abstract/frost.ts';
import * as mod from '../src/abstract/modular.ts';
import { ed25519, ed25519_FROST, ristretto255, ristretto255_FROST } from '../src/ed25519.ts';
import { ed448, ed448_FROST } from '../src/ed448.ts';
import { p256, p256_FROST } from '../src/nist.ts';
import { schnorr, schnorr_FROST, secp256k1, secp256k1_FROST } from '../src/secp256k1.ts';
import { numberToBytesBE, numberToBytesLE } from '../src/utils.ts';
import { json } from './utils.ts';

type ScalarField = {
  fromBytes: (bytes: Uint8Array) => bigint;
  toBytes: (value: bigint) => Uint8Array;
  add: (a: bigint, b: bigint) => bigint;
  ZERO: bigint;
  isLE?: boolean;
  ORDER: bigint;
};
type SignCfg = { MIN_PARTICIPANTS: number | string; MAX_PARTICIPANTS: number | string };
type ParticipantShare = { identifier: number; participant_share: string };
type RoundOneOutput = {
  identifier: number;
  hiding_nonce_randomness: string;
  binding_nonce_randomness: string;
  binding_nonce: string;
  hiding_nonce: string;
  binding_nonce_commitment: string;
  hiding_nonce_commitment: string;
};
type RoundTwoOutput = { identifier: number; sig_share: string };
type SignVector = {
  config: SignCfg;
  inputs: {
    message: string;
    group_secret_key: string;
    verifying_key_key: string;
    share_polynomial_coefficients: string[];
    participant_shares: ParticipantShare[];
  };
  round_one_outputs: { outputs: RoundOneOutput[] };
  round_two_outputs: { outputs: RoundTwoOutput[] };
  final_output: { sig: string };
};
type DkgInput = {
  identifier?: number;
  signing_key?: string;
  coefficient?: string;
  vss_commitments: string[];
  proof_of_knowledge: string;
  signing_shares?: Record<string, string>;
  verifying_share?: string;
};
type DkgVector = {
  config: { MIN_PARTICIPANTS: number; MAX_PARTICIPANTS: number };
  inputs: { verifying_key: string } & Record<string, DkgInput | string>;
};
type SampleVector = {
  identifier: string;
  proof_of_knowledge: string;
  element1: string;
  element2: string;
  scalar1: string;
};
type RepairVector = {
  scalar_generation: Record<string, string>;
  sigma_generation: Record<string, string>;
};
type ElementVector = { elements: { invalid_element: string } };
type PointLike<T> = {
  add(rhs: T): T;
  toBytes(compressed?: boolean): Uint8Array;
};
type PointCtor<T> = {
  BASE: T;
  fromHex(hex: string): T;
};
type Suite = {
  frost: FROST;
  sign: SignVector[];
  dkg: DkgVector[];
  sample: SampleVector;
  repair: RepairVector;
  element: ElementVector;
  base: string;
  doubleBase: string;
  proofPrefix: string;
};
type Actor = {
  id: string;
  secret: Uint8Array;
  round1?: { public: DKG_Round1; secret: DKG_Secret };
  round2?: Record<string, DKG_Round2>;
  round3?: Key;
};

const getJson = <T>(path: string): T => json(path) as T;
const getPointBytes = <P extends PointLike<P>>(Point: PointCtor<P>) => ({
  base: bytesToHex(Point.BASE.toBytes()),
  doubleBase: bytesToHex(Point.BASE.add(Point.BASE).toBytes()),
});
const getVectorsSingle = <P extends PointLike<P>>(
  name: string,
  frost: FROST,
  Point: PointCtor<P>,
  proofPrefix = bytesToHex(Point.BASE.toBytes())
): Suite => ({
  frost,
  sign: [
    getJson<SignVector>(`vectors/rfc9591-frost/${name}-vectors.json`),
    getJson<SignVector>(`vectors/rfc9591-frost/${name}-vectors-big-identifier.json`),
  ],
  dkg: [getJson<DkgVector>(`vectors/rfc9591-frost/${name}-vectors_dkg.json`)],
  sample: getJson<SampleVector>(`vectors/rfc9591-frost/${name}-samples.json`),
  repair: getJson<RepairVector>(`vectors/rfc9591-frost/${name}-repair-share.json`),
  element: getJson<ElementVector>(`vectors/rfc9591-frost/${name}-elements.json`),
  ...getPointBytes(Point),
  proofPrefix,
});
const sumHexScalars = (Fn: ScalarField, values: string[]) => {
  let sum = Fn.ZERO;
  for (const value of values) sum = Fn.add(sum, Fn.fromBytes(hexToBytes(value)));
  return bytesToHex(Fn.toBytes(sum));
};

const VECTORS: Record<string, Suite> = {
  ed25519: getVectorsSingle('ed25519', ed25519_FROST, ed25519.Point),
  ed448: getVectorsSingle('ed448', ed448_FROST, ed448.Point),
  p256: getVectorsSingle('p256', p256_FROST, p256.Point),
  ristretto255: getVectorsSingle('ristretto255', ristretto255_FROST, ristretto255.Point),
  secp256k1: getVectorsSingle('secp256k1', secp256k1_FROST, secp256k1.Point),
  secp256k1_tr: getVectorsSingle(
    'secp256k1-tr',
    schnorr_FROST,
    secp256k1.Point,
    bytesToHex(secp256k1.Point.BASE.toBytes(true).subarray(1))
  ),
};

const Identifiers: Record<string, Record<string, string>> = {
  ed25519: {
    7: '0700000000000000000000000000000000000000000000000000000000000000',
    'alice@example.com': '697dd8ec4846026115571eb037aefc99579c63a39baf715f051069ca393d0d06',
  },
  ed448: {
    7: '070000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
    'alice@example.com':
      'c3d472f37818fe4a273745d83758066066de3c9ed2a2b65ef3d7b5495e0bb3966c965691988afcdcc87a20b711d5890022674c602bf4743b00',
  },
  ristretto255: {
    7: '0700000000000000000000000000000000000000000000000000000000000000',
    'alice@example.com': 'da57abef2150fdc6f5dadb29891f410356c811fd79f987243d037f4c2149990e',
  },
  p256: {
    7: '0000000000000000000000000000000000000000000000000000000000000007',
    'alice@example.com': '2349cacbc2dd7dc5d11f5aa1ff03b9b97f04521eb5147f0f80d6a132c42e596e',
  },
  secp256k1: {
    7: '0000000000000000000000000000000000000000000000000000000000000007',
    'alice@example.com': '961cce175dd5f9864d7f255d5aa9e8cf4e513f8a57df7bcb0dd44793c18980c7',
  },
  secp256k1_tr: {
    7: '0000000000000000000000000000000000000000000000000000000000000007',
    'alice@example.com': '9cfff9f4fb5eb8afd389ff1c9f0f9e2c48e20d85bea2e96fe21773aff1a58301',
  },
};

const BufferRNG = (lst: Uint8Array[]) => {
  return (len: number) => {
    const res = lst.shift();
    if (!res) throw new Error('RNG empty');
    if (res.length !== len) throw new Error(`RNG wrong length ${len} (expected ${res.length})`);
    return res;
  };
};

const MockScalar = (Fn: ScalarField, bytes: Uint8Array) => {
  const n = Fn.fromBytes(bytes);
  return (Fn.isLE ? numberToBytesLE : numberToBytesBE)(n - 1n, mod.getMinHashLength(Fn.ORDER));
};
const secp256k1SecretByY = (even: boolean) => {
  for (let i = 1; i < 512; i++) {
    const secretKey = numberToBytesBE(BigInt(i), 32);
    const point = secp256k1.Point.fromBytes(secp256k1.getPublicKey(secretKey));
    if ((point.y & 1n) === (even ? 0n : 1n)) return secretKey;
  }
  throw new Error('no matching secp256k1 secret key found');
};
const createSession = (frost: FROST, identifiers?: string[]) => {
  const deal = frost.trustedDealer({ min: 2, max: 2 }, identifiers);
  const ids = Object.keys(deal.secretShares);
  const msg = new Uint8Array([1, 2, 3, 4]);
  const secretNonces: Record<string, Nonces> = {};
  const commitmentList: NonceCommitments[] = [];
  for (const id of ids) {
    const { nonces, commitments } = frost.commit(deal.secretShares[id]);
    secretNonces[id] = nonces;
    commitmentList.push(commitments);
  }
  return {
    publicKey: deal.public,
    secretShares: deal.secretShares,
    ids,
    msg,
    secretNonces,
    commitmentList,
  };
};

describe('FROST (RFC 9591)', () => {
  for (const name in VECTORS) {
    const { frost, sign, dkg, sample, repair, element, base, doubleBase, proofPrefix } =
      VECTORS[name];
    describe(`${name}`, () => {
      const Fn = frost.utils.Fn;
      should('Identifiers', () => {
        const t = Identifiers[name];
        eql(frost.Identifier.fromNumber(7), t[7]);
        eql(frost.Identifier.derive('alice@example.com'), t['alice@example.com']);
        throws(() => frost.Identifier.fromNumber(0));
      });
      should('samples', () => {
        eql(frost.Identifier.fromNumber(42), sample.identifier);
        eql(sample.element1, base);
        eql(sample.element2, doubleBase);
        eql(sample.proof_of_knowledge, proofPrefix + sample.scalar1);
        eql(bytesToHex(Fn.toBytes(Fn.fromBytes(hexToBytes(sample.scalar1)))), sample.scalar1);
      });
      should('repair-share fixtures', () => {
        const { scalar_generation: sg, sigma_generation: gg } = repair;
        eql(
          sumHexScalars(Fn, [sg.random_scalar_1, sg.random_scalar_2, sg.random_scalar_3]),
          sg.random_scalar_sum
        );
        eql(sumHexScalars(Fn, [gg.sigma_1, gg.sigma_2, gg.sigma_3, gg.sigma_4]), gg.sigma_sum);
      });
      should('invalid elements', () => {
        const deal = frost.trustedDealer({ min: 2, max: 2 });
        const ids = Object.keys(deal.secretShares);
        const { nonces, commitments } = frost.commit(deal.secretShares[ids[0]]);
        const { commitments: commitments2 } = frost.commit(deal.secretShares[ids[1]]);
        const commitmentList = [
          { ...commitments, hiding: hexToBytes(element.elements.invalid_element) },
          commitments2,
        ];
        throws(() =>
          frost.signShare(
            deal.secretShares[ids[0]],
            deal.public,
            nonces,
            commitmentList,
            new Uint8Array([1, 2, 3])
          )
        );
      });
      const testSign = (publicKey: FrostPublic, secretShares: Record<string, FrostSecret>) => {
        // Round 1: everybody commit nonces
        const secretNonces: Record<string, Nonces> = {};
        const commitmentList: NonceCommitments[] = []; // Nonce commitments from participants merged in commitmentList
        for (const k in secretShares) {
          const { nonces, commitments } = frost.commit(secretShares[k]);
          secretNonces[k] = nonces;
          commitmentList.push(commitments);
        }
        // Round 2: everybody sign message
        const msg = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]);
        const sigShares: Record<string, Uint8Array> = {};
        for (const k in secretShares) {
          sigShares[k] = frost.signShare(
            secretShares[k],
            publicKey,
            secretNonces[k],
            commitmentList,
            msg
          );
        }
        // Each participant (or coordinator) can verify signature shares
        for (const id in secretShares) {
          for (const sid in sigShares) {
            eql(frost.verifyShare(publicKey, commitmentList, msg, sid, sigShares[sid]), true);
          }
        }

        for (const id in secretShares) {
          const groupSig = frost.aggregate(publicKey, commitmentList, msg, sigShares);
          // Verify group signature
          eql(frost.verify(groupSig, msg, publicKey.commitments[0]), true);
        }
      };
      should('Example (DKG, no dealer)', () => {
        // Alice, Bob and Carol decide to create 2-3 multisig (this is outside of protocol)
        const signers = { min: 2, max: 3 };
        const alice: Actor = {
          id: frost.Identifier.derive('alice@example.com'),
          secret: frost.utils.randomScalar(),
        };
        const bob: Actor = {
          id: frost.Identifier.fromNumber(2),
          secret: frost.utils.randomScalar(),
        };
        const carol: Actor = {
          id: frost.Identifier.derive('carol@apt.org'),
          secret: frost.utils.randomScalar(),
        };
        // Everybody prepare round1 packages
        alice.round1 = frost.DKG.round1(alice.id, signers, alice.secret);
        bob.round1 = frost.DKG.round1(bob.id, signers, bob.secret);
        carol.round1 = frost.DKG.round1(carol.id, signers, carol.secret);
        // Now they exchange public information from round1 and do round2
        const aliceRound1Received = [bob.round1.public, carol.round1.public];
        const bobRound1Received = [alice.round1.public, carol.round1.public];
        const carolRound1Received = [bob.round1.public, alice.round1.public];
        alice.round2 = frost.DKG.round2(alice.round1.secret, aliceRound1Received);
        bob.round2 = frost.DKG.round2(bob.round1.secret, bobRound1Received);
        carol.round2 = frost.DKG.round2(carol.round1.secret, carolRound1Received);
        // Now each sends information about round2 to others
        const aliceRound2Received = [bob.round2[alice.id], carol.round2[alice.id]];
        const bobRound2Received = [alice.round2[bob.id], carol.round2[bob.id]];
        const carolRound2Received = [bob.round2[carol.id], alice.round2[carol.id]];
        alice.round3 = frost.DKG.round3(
          alice.round1.secret,
          aliceRound1Received,
          aliceRound2Received
        );
        bob.round3 = frost.DKG.round3(bob.round1.secret, bobRound1Received, bobRound2Received);
        carol.round3 = frost.DKG.round3(
          carol.round1.secret,
          carolRound1Received,
          carolRound2Received
        );
        // previous secrets can be safely removed:
        for (const s of [alice.round1.secret, bob.round1.secret, carol.round1.secret])
          frost.DKG.clean(s);
        const keys = {
          [alice.id]: alice.round3,
          [bob.id]: bob.round3,
          [carol.id]: carol.round3,
        };
        for (const k in keys) frost.validateSecret(keys[k].secret, keys[k].public);
        // Now, with round3 info we can sign stuff
        testSign(alice.round3.public, {
          [alice.id]: alice.round3.secret,
          [bob.id]: bob.round3.secret,
          [carol.id]: carol.round3.secret,
        });
      });
      should('Example (trusted dealer)', () => {
        const signers = { min: 2, max: 3 };
        // Even if no identifiers & secret key provided, we still can generate everything
        // Trusted dealer generates key for everybody
        const keys = frost.trustedDealer(signers);
        // Each participant verify their own key
        for (const k in keys.secretShares) frost.validateSecret(keys.secretShares[k], keys.public);
        // Now participants can sign stuff
        testSign(keys.public, keys.secretShares);
      });
      if (name === 'secp256k1_tr') {
        should('Taproot single-key signing normalizes odd-Y secrets', () => {
          const msg = new Uint8Array([9, 8, 7, 6]);
          const secretKey = secp256k1SecretByY(false);
          const sig = schnorr_FROST.sign(msg, secretKey);
          eql(schnorr_FROST.verify(sig, msg, secp256k1.getPublicKey(secretKey)), true);
        });
        should('Taproot verify accepts x-only pubkeys and rejects SEC1 uncompressed', () => {
          const msg = new Uint8Array([1, 3, 3, 7]);
          const secretKey = secp256k1SecretByY(true);
          const sig = schnorr_FROST.sign(msg, secretKey);
          eql(schnorr_FROST.verify(sig, msg, schnorr.getPublicKey(secretKey)), true);
          throws(() => schnorr_FROST.verify(sig, msg, secp256k1.getPublicKey(secretKey, false)));
        });
      }
      should('reject non-canonical identifier hex', () => {
        const bad = frost.Identifier.fromNumber(11).toUpperCase();
        const good = frost.Identifier.fromNumber(12);
        throws(() => frost.trustedDealer({ min: 2, max: 2 }, [bad, good]));
      });
      should('reject duplicate explicit identifiers in trustedDealer', () => {
        const id = frost.Identifier.fromNumber(7);
        throws(() => frost.trustedDealer({ min: 2, max: 2 }, [id, id]));
      });
      should('trustedDealer returns one shared public package', () => {
        const deal = frost.trustedDealer({ min: 2, max: 2 });
        eql(Object.keys(deal).sort(), ['public', 'secretShares']);
        eql(Object.keys(deal.public).sort(), ['commitments', 'signers', 'verifyingShares']);
        eql(deal.public.signers, { min: 2, max: 2 });
      });
      should('trustedDealer secrets do not alias commitment buffers', () => {
        const deal = frost.trustedDealer({ min: 2, max: 2 });
        const before = Uint8Array.from(deal.public.commitments[0]);
        deal.secretShares[Object.keys(deal.secretShares)[0]].signingShare[0] ^= 1;
        eql(deal.public.commitments[0], before);
      });
      should('DKG round3 does not alias public and secret buffers', () => {
        const signers = { min: 2, max: 2 };
        const alice = frost.DKG.round1(frost.Identifier.fromNumber(1), signers);
        const bob = frost.DKG.round1(frost.Identifier.fromNumber(2), signers);
        const aliceRound2 = frost.DKG.round2(alice.secret, [bob.public]);
        const bobRound2 = frost.DKG.round2(bob.secret, [alice.public]);
        const round3 = frost.DKG.round3(
          alice.secret,
          [bob.public],
          [bobRound2[frost.Identifier.fromNumber(1)]]
        );
        const before = Uint8Array.from(
          round3.public.verifyingShares[frost.Identifier.fromNumber(1)]
        );
        round3.public.commitments[0][0] ^= 1;
        eql(round3.public.verifyingShares[frost.Identifier.fromNumber(1)], before);
      });
      should('normalize unsorted commitment lists', () => {
        const { publicKey, secretShares, ids, msg, secretNonces, commitmentList } =
          createSession(frost);
        const sortedShare = frost.signShare(
          secretShares[ids[0]],
          publicKey,
          secretNonces[ids[0]],
          commitmentList,
          msg
        );
        const reversed = [...commitmentList].reverse();
        const reversedShare = frost.signShare(
          secretShares[ids[0]],
          publicKey,
          secretNonces[ids[0]],
          reversed,
          msg
        );
        eql(reversedShare, sortedShare);
      });
      should('reject mismatched signer commitment pairs', () => {
        const { publicKey, secretShares, ids, msg, secretNonces, commitmentList } =
          createSession(frost);
        const tampered = [...commitmentList];
        tampered[0] = {
          ...tampered[0],
          hiding: tampered[1].hiding,
          binding: tampered[1].binding,
        };
        throws(() =>
          frost.signShare(secretShares[ids[0]], publicKey, secretNonces[ids[0]], tampered, msg)
        );
      });
      should('reject under-threshold signing sessions before share generation', () => {
        const signers = { min: 2, max: 3 };
        const deal = frost.trustedDealer(signers);
        const id = Object.keys(deal.secretShares)[0];
        const { nonces, commitments } = frost.commit(deal.secretShares[id]);
        throws(() =>
          frost.signShare(
            deal.secretShares[id],
            deal.public,
            nonces,
            [commitments],
            new Uint8Array([1, 2, 3])
          )
        );
      });
      should('reject over-capacity signing sessions before share generation', () => {
        const deal = frost.trustedDealer({ min: 2, max: 2 });
        const id = Object.keys(deal.secretShares)[0];
        const { nonces, commitments } = frost.commit(deal.secretShares[id]);
        const extra = { ...commitments, identifier: frost.Identifier.fromNumber(3) };
        throws(() =>
          frost.signShare(
            deal.secretShares[id],
            deal.public,
            nonces,
            [commitments, commitments, extra],
            new Uint8Array([1, 2, 3])
          )
        );
      });
      should('combineSecret rejects duplicate shares beyond threshold', () => {
        const signers = { min: 2, max: 3 };
        const deal = frost.trustedDealer(signers);
        const ids = Object.keys(deal.secretShares);
        throws(() =>
          frost.combineSecret(
            [deal.secretShares[ids[0]], deal.secretShares[ids[1]], deal.secretShares[ids[0]]],
            signers
          )
        );
      });
      should('reject renamed signature shares during aggregation', () => {
        const { publicKey, secretShares, ids, msg, commitmentList, secretNonces } =
          createSession(frost);
        const sigShares: Record<string, Uint8Array> = {};
        for (const id of ids)
          sigShares[id] = frost.signShare(
            secretShares[id],
            publicKey,
            secretNonces[id],
            commitmentList,
            msg
          );
        const renamed: Record<string, Uint8Array> = {
          [frost.Identifier.fromNumber(10)]: sigShares[ids[0]],
          [frost.Identifier.fromNumber(11)]: sigShares[ids[1]],
        };
        throws(() => frost.aggregate(publicKey, commitmentList, msg, renamed));
      });
      should('DKG round2 rejects caller package in others', () => {
        const signers = { min: 2, max: 3 };
        const alice = frost.DKG.round1(frost.Identifier.fromNumber(1), signers);
        const bob = frost.DKG.round1(frost.Identifier.fromNumber(2), signers);
        throws(() => frost.DKG.round2(alice.secret, [alice.public, bob.public]));
      });
      should('DKG round2 rejects malformed higher commitments', () => {
        const signers = { min: 2, max: 3 };
        const alice = frost.DKG.round1(frost.Identifier.fromNumber(1), signers);
        const bob = frost.DKG.round1(frost.Identifier.fromNumber(2), signers);
        const carol = frost.DKG.round1(frost.Identifier.fromNumber(3), signers);
        const malformed = { ...bob.public, commitment: [...bob.public.commitment] };
        malformed.commitment[1] = new Uint8Array([1]);
        throws(() => frost.DKG.round2(alice.secret, [malformed, carol.public]));
      });
      should('DKG clean does not mutate shared signers state', () => {
        const signers = { min: 2, max: 3 };
        const alice = frost.DKG.round1(frost.Identifier.fromNumber(1), signers);
        const bob = frost.DKG.round1(frost.Identifier.fromNumber(2), signers);
        frost.DKG.clean(alice.secret);
        eql(signers, { min: 2, max: 3 });
        eql(alice.secret.signers, { min: 2, max: 3 });
        eql(bob.secret.signers, { min: 2, max: 3 });
      });
      should('DKG round3 rejects tampered local secret state', () => {
        const signers = { min: 2, max: 2 };
        const alice = frost.DKG.round1(frost.Identifier.fromNumber(1), signers);
        const bob = frost.DKG.round1(frost.Identifier.fromNumber(2), signers);
        frost.DKG.round2(alice.secret, [bob.public]);
        const bobRound2 = frost.DKG.round2(bob.secret, [alice.public]);
        alice.secret.coefficients![0] += 1n;
        throws(() =>
          frost.DKG.round3(alice.secret, [bob.public], [bobRound2[frost.Identifier.fromNumber(1)]])
        );
      });
      should('DKG round2 can retry after a late round3 failure', () => {
        const signers = { min: 2, max: 2 };
        const alice = frost.DKG.round1(frost.Identifier.fromNumber(1), signers);
        const bob = frost.DKG.round1(frost.Identifier.fromNumber(2), signers);
        const first = frost.DKG.round2(alice.secret, [bob.public]);
        const bobRound2 = frost.DKG.round2(bob.secret, [alice.public]);
        const commitment0 = alice.secret.commitment[0];
        alice.secret.commitment[0] = new Uint8Array([1]);
        throws(() =>
          frost.DKG.round3(alice.secret, [bob.public], [bobRound2[frost.Identifier.fromNumber(1)]])
        );
        alice.secret.commitment[0] = commitment0;
        eql(frost.DKG.round2(alice.secret, [bob.public]), first);
      });
      let i = 0;

      for (const t of sign) {
        should(`sign ${i++}`, () => {
          const signers = { min: +t.config.MIN_PARTICIPANTS, max: +t.config.MAX_PARTICIPANTS };
          const msg = hexToBytes(t.inputs.message);
          const secretKey = hexToBytes(t.inputs.group_secret_key);
          // 0. Trusted dealear generates keys for multisig
          const deal = frost.trustedDealer(
            signers,
            undefined,
            secretKey,
            BufferRNG([
              ...t.inputs.share_polynomial_coefficients.map((i) => MockScalar(Fn, hexToBytes(i))),
            ])
          );
          const ids = Object.keys(deal.secretShares);
          for (const id of ids)
            eql(bytesToHex(deal.public.commitments[0]), t.inputs.verifying_key_key);
          // We can combine shards back to key
          eql(
            bytesToHex(
              frost.combineSecret(
                ids.map((i) => deal.secretShares[i]),
                signers
              )
            ),
            t.inputs.group_secret_key
          );
          // Use combine secret key to sign & verify
          const sigGroup = frost.sign(msg, hexToBytes(t.inputs.group_secret_key));
          eql(frost.verify(sigGroup, msg, hexToBytes(t.inputs.verifying_key_key)), true);
          // Validate generated shares
          for (const ps of t.inputs.participant_shares) {
            const id = ids[ps.identifier - 1];
            eql(frost.Identifier.fromNumber(ps.identifier), id);
            eql(bytesToHex(deal.secretShares[id].signingShare), ps.participant_share);
          }
          // Then dealer sends keys to everybody. Each participant validates secret share
          for (const k in deal.secretShares)
            frost.validateSecret(deal.secretShares[k], deal.public);
          // Round 1: each participant generate nonce and commitments
          // Nonces kept private, commitments sent to coordinator (or every other participant)
          const secretNonces: Record<string, Nonces> = {};
          const commitmentList: NonceCommitments[] = []; // Nonce commitments from participants merged in commitmentList
          for (const o of t.round_one_outputs.outputs) {
            const id = ids[o.identifier - 1];
            const { nonces, commitments } = frost.commit(
              deal.secretShares[id],
              BufferRNG(
                [o.hiding_nonce_randomness, o.binding_nonce_randomness].map((i) => hexToBytes(i))
              )
            );
            eql(bytesToHex(nonces.binding), o.binding_nonce);
            eql(bytesToHex(nonces.hiding), o.hiding_nonce);
            eql(bytesToHex(commitments.binding), o.binding_nonce_commitment);
            eql(bytesToHex(commitments.hiding), o.hiding_nonce_commitment);
            eql(commitments.identifier, id);
            secretNonces[id] = nonces;
            commitmentList.push(commitments);
          }
          // Round 2: each participant signs message
          const sigShares: Record<string, Uint8Array> = {};
          for (const o of t.round_two_outputs.outputs) {
            const id = ids[o.identifier - 1];
            const sigShare = frost.signShare(
              deal.secretShares[id],
              deal.public,
              secretNonces[id],
              commitmentList,
              msg
            );
            eql(bytesToHex(sigShare), o.sig_share);
            sigShares[id] = sigShare;
          }
          // Now, each participant (or coodrinator) can verify signature shares using public key
          for (const id of ids) {
            for (const sid in sigShares) {
              eql(frost.verifyShare(deal.public, commitmentList, msg, sid, sigShares[sid]), true);
            }
          }
          // Final: all participants (or coordinator) merge signature shares into single group signature
          for (const id of ids) {
            const groupSig = frost.aggregate(deal.public, commitmentList, msg, sigShares);
            eql(bytesToHex(groupSig), t.final_output.sig);
            // Verify group signature
            eql(frost.verify(groupSig, msg, deal.public.commitments[0]), true);
          }
        });
      }
      i = 0;
      for (const t of dkg) {
        // DKG is Distributed Key Generation (not related to Trusted Dealer Key Generation)
        // Awesome naming!
        should(`dkg ${i++}`, () => {
          const getInput = (id: number): DkgInput => {
            const input = t.inputs[String(id)];
            if (!input || typeof input === 'string') throw new Error('missing DKG input ' + id);
            return input;
          };
          // Official tests check only participant 1, this part of test vectors is broken.
          // We replace invalid value with real (verified with official implementation).
          if (name === 'ed448') {
            const input = getInput(3);
            if (!input.signing_shares) throw new Error('missing ed448 signing shares');
            input.signing_shares['2'] = bytesToHex(
              new Uint8Array([
                106, 167, 228, 143, 61, 127, 77, 227, 177, 160, 187, 149, 165, 8, 87, 5, 229, 97,
                139, 143, 103, 216, 156, 244, 61, 216, 214, 73, 5, 125, 41, 95, 240, 200, 55, 228,
                169, 24, 99, 74, 148, 167, 115, 96, 110, 209, 86, 201, 219, 84, 60, 59, 205, 30, 42,
                14, 0,
              ])
            );
          }
          const signers = { min: t.config.MIN_PARTICIPANTS, max: t.config.MAX_PARTICIPANTS };
          const ids: number[] = [];
          const round1: Record<number, DKG_Round1> = {};
          const round1Secret: Record<number, DKG_Secret> = {};
          const round2Recv: Record<number, DKG_Round2[]> = {};
          const id2id: Record<string, number> = {};
          for (const k in t.inputs) {
            const v = t.inputs[k];
            if (typeof v === 'string' || !v.identifier) continue;
            const id = +v.identifier;
            id2id[frost.Identifier.fromNumber(id)] = id;
            ids.push(id);
            round1[id] = {
              identifier: frost.Identifier.fromNumber(id),
              commitment: v.vss_commitments.map(hexToBytes),
              proofOfKnowledge: hexToBytes(v.proof_of_knowledge),
            };
            if (!v.signing_key) continue;
            const { coefficients, commitment } = frost.utils.generateSecretPolynomial(
              signers,
              hexToBytes(v.signing_key),
              [Fn.fromBytes(hexToBytes(v.coefficient))]
            );
            // Re-create first round package, because we don't have random info in tests
            const identifier = Fn.fromBytes(hexToBytes(frost.Identifier.fromNumber(id)));
            round1Secret[id] = {
              identifier,
              coefficients,
              commitment,
              signers,
            };
            // What we receive from others
            const shares = [];
            for (const k in v.signing_shares) {
              shares.push({
                identifier: frost.Identifier.fromNumber(+k),
                signingShare: hexToBytes(v.signing_shares[k]),
              });
            }
            round2Recv[id] = shares;
          }
          for (const id of ids) {
            const other = ids.filter((i) => i !== id);
            if (round1Secret[id]) {
              const otherSecretShares = {};
              for (const otherId of other) {
                const input = getInput(otherId);
                if (!input.signing_shares) continue;
                otherSecretShares[frost.Identifier.fromNumber(otherId)] = hexToBytes(
                  input.signing_shares[String(id)]
                );
              }
              // Skip inputs without info (broken in taproot stuff)
              const input = getInput(id);
              if (!input.signing_shares) continue;
              // What we send
              const round2 = frost.DKG.round2(
                round1Secret[id],
                other.map((i) => round1[i])
              );
              for (const k in round2) {
                if (!otherSecretShares[k]) continue;
                eql(round2[k].signingShare, otherSecretShares[k]);
              }
              if (!round2Recv[id].length) continue;

              // What we receive
              const round3 = frost.DKG.round3(
                round1Secret[id],
                other.map((i) => round1[i]),
                round2Recv[id]
              );
              eql(round3.public.commitments[0], hexToBytes(t.inputs.verifying_key));
              for (const k in round3.public.verifyingShares) {
                const v = round3.public.verifyingShares[k];
                eql(v, hexToBytes(getInput(id2id[k]).verifying_share!));
              }
            }
          }
        });
      }
    });
  }
});

should.runWhen(import.meta.url);
