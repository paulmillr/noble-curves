/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { sha224, sha256, sha512 } from '@noble/hashes/sha2';
import { createCurve } from '../esm/_shortw_utils.js';
import { Field } from '../esm/abstract/modular.js';
import curvesInit from './vectors/curves-init.json' with { type: 'json' };
const { categories: JSON_CATEGORIES } = curvesInit;

// NIST secp192r1 aka p192
// https://www.secg.org/sec2-v2.pdf, https://neuromancer.sk/std/secg/secp192r1
export const p192 = createCurve(
  {
    // Params: a, b
    a: BigInt('0xfffffffffffffffffffffffffffffffefffffffffffffffc'),
    b: BigInt('0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1'),
    // Field over which we'll do calculations; 2n ** 192n - 2n ** 64n - 1n
    Fp: Field(BigInt('0xfffffffffffffffffffffffffffffffeffffffffffffffff')),
    // Curve order, total count of valid points in the field.
    n: BigInt('0xffffffffffffffffffffffff99def836146bc9b1b4d22831'),
    // Base point (x, y) aka generator point
    Gx: BigInt('0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012'),
    Gy: BigInt('0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811'),
    h: BigInt(1),
    lowS: false,
  },
  sha256
);
export const secp192r1 = p192;

export const p224 = createCurve(
  {
    // Params: a, b
    a: BigInt('0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe'),
    b: BigInt('0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4'),
    // Field over which we'll do calculations;
    Fp: Field(BigInt('0xffffffffffffffffffffffffffffffff000000000000000000000001')),
    // Curve order, total count of valid points in the field
    n: BigInt('0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d'),
    // Base point (x, y) aka generator point
    Gx: BigInt('0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21'),
    Gy: BigInt('0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34'),
    h: BigInt(1),
    lowS: false,
  },
  sha224
);
export const secp224r1 = p224;

// NIST Curves

const SECP192R1 = {
  p: '0xfffffffffffffffffffffffffffffffeffffffffffffffff',
  a: '0xfffffffffffffffffffffffffffffffefffffffffffffffc',
  b: '0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1',
  Gx: '0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012',
  Gy: '0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811',
  n: '0xffffffffffffffffffffffff99def836146bc9b1b4d22831',
  h: '0x1',
  oid: '1.2.840.10045.3.1.1',
};

const SECP224R1 = {
  p: '0xffffffffffffffffffffffffffffffff000000000000000000000001',
  a: '0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe',
  b: '0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4',
  Gx: '0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21',
  Gy: '0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34',
  n: '0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d',
  h: '0x1',
  oid: '1.3.132.0.33',
};

const SECP256K1 = {
  p: '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
  a: '0x0',
  b: '0x7',
  Gx: '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  Gy: '0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
  n: '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  h: '0x1',
  oid: '1.3.132.0.10',
};

const SECP384R1 = {
  p: '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff',
  a: '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc',
  b: '0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef',
  Gx: '0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7',
  Gy: '0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f',
  n: '0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',
  h: '0x1',
  oid: '1.3.132.0.34',
};

const SECP521R1 = {
  p: '0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  a: '0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc',
  b: '0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00',
  Gx: '0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66',
  Gy: '0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650',
  n: '0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409',
  h: '0x1',
  oid: '1.3.132.0.35',
};

// SEC Koblitz Curves

const SECP192K1 = {
  p: '0xfffffffffffffffffffffffffffffffffffffffeffffee37',
  a: '0x0',
  b: '0x3',
  Gx: '0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d',
  Gy: '0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d',
  n: '0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d',
  h: '0x1',
  oid: '1.3.132.0.31',
};

const SECP224K1 = {
  p: '0xfffffffffffffffffffffffffffffffffffffffffffffffeffffe56d',
  a: '0x0',
  b: '0x5',
  Gx: '0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c',
  Gy: '0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5',
  n: '0x010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7',
  h: '0x1',
  oid: '1.3.132.0.32',
};

// SEC 2 Alternative Curves

const SECP128R1 = {
  p: '0xfffffffdffffffffffffffffffffffff',
  a: '0xfffffffdfffffffffffffffffffffffc',
  b: '0xe87579c11079f43dd824993c2cee5ed3',
  Gx: '0x161ff7528b899b2d0c28607ca52c5b86',
  Gy: '0xcf5ac8395bafeb13c02da292dded7a83',
  n: '0xfffffffe0000000075a30d1b9038a115',
  h: '0x1',
  oid: '1.3.132.0.28',
};

const SECP128R2 = {
  p: '0xfffffffdffffffffffffffffffffffff',
  a: '0xd6031998d1b3bbfebf59cc9bbff9aee1',
  b: '0x5eeefca380d02919dc2c6558bb6d8a5d',
  Gx: '0x7b6aa5d85e572983e6fb32a7cdebc140',
  Gy: '0x27b6916a894d3aee7106fe805fc34b44',
  n: '0x3fffffff7fffffffbe0024720613b5a3',
  h: '0x4',
  oid: '1.3.132.0.29',
};

const SECP160K1 = {
  p: '0xfffffffffffffffffffffffffffffffeffffac73',
  a: '0x0',
  b: '0x7',
  Gx: '0x3b4c382ce37aa192a4019e763036f4f5dd4d7ebb',
  Gy: '0x938cf935318fdced6bc28286531733c3f03c4fee',
  n: '0x100000000000000000001b8fa16dfab9aca16b6b3',
  h: '0x1',
  oid: '1.3.132.0.9',
};

const SECP160R1 = {
  p: '0xffffffffffffffffffffffffffffffff7fffffff',
  a: '0xffffffffffffffffffffffffffffffff7ffffffc',
  b: '0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45',
  Gx: '0x4a96b5688ef573284664698968c38bb913cbfc82',
  Gy: '0x23a628553168947d59dcc912042351377ac5fb32',
  n: '0x100000000000000000001f4c8f927aed3ca752257',
  h: '0x1',
  oid: '1.3.132.0.8',
};

const SECP160R2 = {
  p: '0xfffffffffffffffffffffffffffffffeffffac73',
  a: '0xfffffffffffffffffffffffffffffffeffffac70',
  b: '0xb4e134d3fb59eb8bab57274904664d5af50388ba',
  Gx: '0x52dcb034293a117e1f4ff11b30f7199d3144ce6d',
  Gy: '0xfeaffef2e331f296e071fa0df9982cfea7d43f2e',
  n: '0x100000000000000000000351ee786a818f3a1a16b',
  h: '0x1',
  oid: '1.3.132.0.30',
};

// Brainpool Standard Curves

const BRAINPOOLP160R1 = {
  p: '0xe95e4a5f737059dc60dfc7ad95b3d8139515620f',
  a: '0x340e7be2a280eb74e2be61bada745d97e8f7c300',
  b: '0x1e589a8595423412134faa2dbdec95c8d8675e58',
  Gx: '0xbed5af16ea3f6a4f62938c4631eb5af7bdbcdbc3',
  Gy: '0x1667cb477a1a8ec338f94741669c976316da6321',
  n: '0xe95e4a5f737059dc60df5991d45029409e60fc09',
  h: '0x1',
  oid: '1.3.36.3.3.2.8.1.1.1',
};

const BRAINPOOLP160T1 = {
  p: '0xe95e4a5f737059dc60dfc7ad95b3d8139515620f',
  a: '0xe95e4a5f737059dc60dfc7ad95b3d8139515620c',
  b: '0x7a556b6dae535b7b51ed2c4d7daa7a0b5c55f380',
  Gx: '0xb199b13b9b34efc1397e64baeb05acc265ff2378',
  Gy: '0xadd6718b7c7c1961f0991b842443772152c9e0ad',
  n: '0xe95e4a5f737059dc60df5991d45029409e60fc09',
  h: '0x1',
  oid: '1.3.36.3.3.2.8.1.1.2',
};

const BRAINPOOLP192R1 = {
  p: '0xc302f41d932a36cda7a3463093d18db78fce476de1a86297',
  a: '0x6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef',
  b: '0x469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9',
  Gx: '0xc0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd6',
  Gy: '0x14b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f',
  n: '0xc302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1',
  h: '0x1',
  oid: '1.3.36.3.3.2.8.1.1.3',
};

const BRAINPOOLP192T1 = {
  p: '0xc302f41d932a36cda7a3463093d18db78fce476de1a86297',
  a: '0xc302f41d932a36cda7a3463093d18db78fce476de1a86294',
  b: '0x13d56ffaec78681e68f9deb43b35bec2fb68542e27897b79',
  Gx: '0x3ae9e58c82f63c30282e1fe7bbf43fa72c446af6f4618129',
  Gy: '0x97e2c5667c2223a902ab5ca449d0084b7e5b3de7ccc01c9',
  n: '0xc302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1',
  h: '0x1',
  oid: '1.3.36.3.3.2.8.1.1.4',
};

const BRAINPOOLP224R1 = {
  p: '0xd7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff',
  a: '0x68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43',
  b: '0x2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b',
  Gx: '0xd9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d',
  Gy: '0x58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd',
  n: '0xd7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f',
  h: '0x1',
  oid: '1.3.36.3.3.2.8.1.1.5',
};

const BRAINPOOLP224T1 = {
  p: '0xd7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff',
  a: '0xd7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0fc',
  b: '0x4b337d934104cd7bef271bf60ced1ed20da14c08b3bb64f18a60888d',
  Gx: '0x6ab1e344ce25ff3896424e7ffe14762ecb49f8928ac0c76029b4d580',
  Gy: '0x374e9f5143e568cd23f3f4d7c0d4b1e41c8cc0d1c6abd5f1a46db4c',
  n: '0xd7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f',
  h: '0x1',
  oid: '1.3.36.3.3.2.8.1.1.6',
};

const BRAINPOOLP256R1 = {
  p: '0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377',
  a: '0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9',
  b: '0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6',
  Gx: '0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262',
  Gy: '0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997',
  n: '0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7',
  h: '0x1',
  oid: '1.3.36.3.3.2.8.1.1.7',
};

const BRAINPOOLP256T1 = {
  p: '0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377',
  a: '0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5374',
  b: '0x662c61c430d84ea4fe66a7733d0b76b7bf93ebc4af2f49256ae58101fee92b04',
  Gx: '0xa3e8eb3cc1cfe7b7732213b23a656149afa142c47aafbc2b79a191562e1305f4',
  Gy: '0x2d996c823439c56d7f7b22e14644417e69bcb6de39d027001dabe8f35b25c9be',
  n: '0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7',
  h: '0x1',
  oid: '1.3.36.3.3.2.8.1.1.8',
};

const BRAINPOOLP320R1 = {
  p: '0xd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27',
  a: '0x3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4',
  b: '0x520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6',
  Gx: '0x43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611',
  Gy: '0x14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1',
  n: '0xd35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311',
  h: '0x1',
  oid: '1.3.36.3.3.2.8.1.1.9',
};

const BRAINPOOLP320T1 = {
  p: '0xd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27',
  a: '0xd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e24',
  b: '0xa7f561e038eb1ed560b3d147db782013064c19f27ed27c6780aaf77fb8a547ceb5b4fef422340353',
  Gx: '0x925be9fb01afc6fb4d3e7d4990010f813408ab106c4f09cb7ee07868cc136fff3357f624a21bed52',
  Gy: '0x63ba3a7a27483ebf6671dbef7abb30ebee084e58a0b077ad42a5a0989d1ee71b1b9bc0455fb0d2c3',
  n: '0xd35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311',
  h: '0x1',
  oid: '1.3.36.3.3.2.8.1.1.10',
};

const BRAINPOOLP384R1 = {
  p: '0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53',
  a: '0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826',
  b: '0x04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11',
  Gx: '0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e',
  Gy: '0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315',
  n: '0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565',
  h: '0x1',
  oid: '1.3.36.3.3.2.8.1.1.11',
};

const BRAINPOOLP384T1 = {
  p: '0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53',
  a: '0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec50',
  b: '0x7f519eada7bda81bd826dba647910f8c4b9346ed8ccdc64e4b1abd11756dce1d2074aa263b88805ced70355a33b471ee',
  Gx: '0x18de98b02db9a306f2afcd7235f72a819b80ab12ebd653172476fecd462aabffc4ff191b946a5f54d8d0aa2f418808cc',
  Gy: '0x25ab056962d30651a114afd2755ad336747f93475b7a1fca3b88f2b6a208ccfe469408584dc2b2912675bf5b9e582928',
  n: '0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565',
  h: '0x1',
  oid: '1.3.36.3.3.2.8.1.1.12',
};

const BRAINPOOLP512R1 = {
  p: '0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3',
  a: '0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca',
  b: '0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723',
  Gx: '0x81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822',
  Gy: '0x7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892',
  n: '0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069',
  h: '0x1',
  oid: '1.3.36.3.3.2.8.1.1.13',
};

const BRAINPOOLP512T1 = {
  p: '0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3',
  a: '0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f0',
  b: '0x7cbbbcf9441cfab76e1890e46884eae321f70c0bcb4981527897504bec3e36a62bcdfa2304976540f6450085f2dae145c22553b465763689180ea2571867423e',
  Gx: '0x640ece5c12788717b9c1ba06cbc2a6feba85842458c56dde9db1758d39c0313d82ba51735cdb3ea499aa77a7d6943a64f7a3f25fe26f06b51baa2696fa9035da',
  Gy: '0x5b534bd595f5af0fa2c892376c84ace1bb4e3019b71634c01131159cae03cee9d9932184beef216bd71df2dadf86a627306ecff96dbb8bace198b61e00f8b332',
  n: '0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069',
  h: '0x1',
  oid: '1.3.36.3.3.2.8.1.1.14',
};

// French Curve
const FRP256V1 = {
  p: '0xf1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c03',
  a: '0xf1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c00',
  b: '0xee353fca5428a9300d4aba754a44c00fdfec0c9ae4b1a1803075ed967b7bb73f',
  Gx: '0xb6b3d4c356c139eb31183d4749d423958c27d2dcaf98b70164c97a2dd98f5cff',
  Gy: '0x6142e0f7c8b204911f9271f0f3ecef8c2701c307e8e4c9e183115a1554062cfb',
  n: '0xf1fd178c0b3ad58f10126de8ce42435b53dc67e140d2bf941ffdd459c6d655e1',
  h: '0x1',
  oid: '1.2.250.1.223.101.256.1',
};

const curvesRaw = {
  // SECP192R1,
  // SECP224R1,
  // SECP256K1,
  // SECP384R1,
  // SECP521R1,
  SECP192K1,
  SECP224K1,
  SECP128R1,
  SECP128R2,
  SECP160K1,
  SECP160R1,
  SECP160R2,
  BRAINPOOLP160R1,
  BRAINPOOLP160T1,
  BRAINPOOLP192R1,
  BRAINPOOLP192T1,
  BRAINPOOLP224R1,
  BRAINPOOLP224T1,
  BRAINPOOLP256R1,
  BRAINPOOLP256T1,
  BRAINPOOLP320R1,
  BRAINPOOLP320T1,
  BRAINPOOLP384R1,
  BRAINPOOLP384T1,
  BRAINPOOLP512R1,
  BRAINPOOLP512T1,
  FRP256V1,
};
export const miscCurves = {};

const big = (str) => BigInt(str);

for (let [name, e] of Object.entries(curvesRaw)) {
  // console.log(name);
  const Fp = Field(BigInt(e.p));
  const a = big(e.a);
  const b = big(e.b);
  const Gx = big(e.Gx);
  const Gy = big(e.Gy);
  const n = big(e.n);
  const h = big(e.h);
  const oid = e.oid;
  const norm = {
    Fp,
    a,
    b,
    Gx,
    Gy,
    n,
    h,
    oid,
  };
  if (name === 'SECP224K1') {
    // norm.nByteLength = 30;
    // norm.allowedPrivateKeyLengths = [58, 59, 60];
  }
  miscCurves[name] = createCurve(norm, sha256);
}

for (let category of JSON_CATEGORIES) {
  for (let curve of category.curves) {
    if (curve.form !== 'Weierstrass') continue;
    if (curve.field.type !== 'Prime') continue;
    if (!curve.generator) continue;
    const a = big(curve.params.a?.raw);
    const b = big(curve.params.b?.raw);
    const Gx = big(curve.generator?.x.raw);
    const Gy = big(curve.generator?.y.raw);
    const n = big(curve.order);
    const h = big(curve.cofactor);
    const p = big(curve.field.p);
    const Fp = Field(p);
    const norm = {
      Fp,
      a,
      b,
      Gx,
      Gy,
      n,
      h,
    };
    miscCurves[curve.name] = createCurve(norm, sha512);
  }
}
