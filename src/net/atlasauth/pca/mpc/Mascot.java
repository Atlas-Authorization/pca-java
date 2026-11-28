package net.atlasauth.pca.mpc;

import static net.atlasauth.pca.mpc.Field.fadd;
import static net.atlasauth.pca.mpc.Field.fmul;
import static net.atlasauth.pca.mpc.Field.fneg;
import static net.atlasauth.pca.mpc.Field.fsub;
import static net.atlasauth.pca.mpc.Field.mod;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import net.atlasauth.pca.mpc.Enc.EncShare;
import net.atlasauth.pca.mpc.Field.FieldRng;
import net.atlasauth.pca.mpc.Ot.OtChannel;
import net.atlasauth.pca.mpc.Ot.OtRandom;
import net.atlasauth.pca.mpc.Spdz.AuthSV;
import net.atlasauth.pca.mpc.Spdz.AuthTriple;
import net.atlasauth.pca.mpc.Spdz.MacCheckAbort;
import net.atlasauth.pca.mpc.Spdz.MacContext;
import net.atlasauth.pca.mpc.Spdz.MacKey;
import net.atlasauth.pca.mpc.Spdz.SpdzEngine;
import net.atlasauth.pca.mpc.Spdz.TripleWithPartners;

/**
 * The no-dealer SPDZ offline phase (MASCOT-style): every product of two additively shared values is built from real
 * oblivious transfers (Gilboa multiplication over OT extension), the MAC key is distributed and never reconstructed, and
 * every produced triple is certified by the sacrifice check. When a check fails the OT transcripts are searched to blame the
 * cheating party.
 */
public final class Mascot {
    private Mascot() {}

    /** A MAC-check abort raised by the offline phase, naming the party the OT transcripts convict (when one can be named). */
    public static final class OfflineCheatingAbort extends MacCheckAbort {
        private final List<Integer> blamed;
        public OfflineCheatingAbort(String message, List<Integer> blamed) {
            super(blamed.isEmpty() ? message : message + "; offline OT transcript names party " + join(blamed));
            this.blamed = blamed;
        }
        public List<Integer> blamed() { return blamed; }
        private static String join(List<Integer> l) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < l.size(); i++) sb.append(i == 0 ? "" : ", ").append(l.get(i));
            return sb.toString();
        }
    }

    private record OtRecord(int receiver, int sender, BigInteger[] msg0, BigInteger[] msg1, BigInteger[] received) {}

    private record ProductClaim(BigInteger[] claimed, BigInteger[] implied) {}

    /** TEST-ONLY: the productMul-th product's claimed share is shifted by delta (a cheating party lying about a product). */
    public record OfflineDeviation(int productMul, BigInteger delta) {}

    /** Options (null fields mean the defaults). */
    public static final class NoDealerOptions {
        public Boolean sacrifice;
        public Integer sacrificePartners;
        public Integer macKeys;
        public OfflineDeviation deviation;
        public Integer statSec;
        public boolean unsafeStatSec;
    }

    /** One operand of a multiplication request: either a plain value or an encoded (value, choice bits) share. */
    private record Req(List<Object> x, BigInteger[] y) {}

    private record Part(int[] bits, BigInteger[] gad) {}

    private record Piece(BigInteger value, List<Part> parts) {}

    private record Seg(int q, int start, int len, BigInteger senderSum) {}

    public static final class NoDealerOffline implements OfflineProvider {
        public final int n;
        public final BigInteger[] alphaShares;
        private final BigInteger[][] keyShares;
        private final EncShare[][] keyEnc;
        private final BigInteger[] gadget;
        public final int statSec;
        private final int sacrificePartners;
        private final FieldRng rng;
        private final BigInteger seed;
        private final boolean deterministic;
        private final Map<String, OtChannel> channels = new HashMap<>();
        private final boolean sacrificeOn;
        private final OfflineDeviation deviation;
        private int productMulCount = 0;
        private List<OtRecord> log = null;
        private List<ProductClaim> claims = new ArrayList<>();

        public NoDealerOffline(int n, BigInteger seed, NoDealerOptions opts) {
            if (opts == null) opts = new NoDealerOptions();
            if (n < 1) throw new IllegalArgumentException("NoDealerOffline: n must be a positive integer");
            this.n = n;
            this.deterministic = seed != null;
            this.seed = seed != null ? seed : new BigInteger("abcdef12345", 16);
            this.rng = deterministic ? new FieldRng(this.seed) : new Field.SecureFieldRng();
            this.sacrificeOn = opts.sacrifice == null || opts.sacrifice;
            this.deviation = opts.deviation;
            int keys = opts.macKeys == null ? Spdz.MAC_KEYS : opts.macKeys;
            if (keys < 1 || keys > 16) throw new IllegalArgumentException("NoDealerOffline: macKeys must be an integer in [1, 16]");
            this.statSec = opts.statSec == null ? Enc.STAT_SEC : opts.statSec;
            this.gadget = Enc.makeGadget(statSec, rng, opts.unsafeStatSec);
            this.keyEnc = new EncShare[keys][n];
            for (int l = 0; l < keys; l++) for (int i = 0; i < n; i++) keyEnc[l][i] = Enc.sampleEnc(gadget, rng);
            this.keyShares = new BigInteger[keys][n];
            for (int l = 0; l < keys; l++) for (int i = 0; i < n; i++) keyShares[l][i] = keyEnc[l][i].value();
            this.alphaShares = keyShares[0];
            this.sacrificePartners = opts.sacrificePartners == null ? Spdz.SACRIFICE_PARTNERS : opts.sacrificePartners;
            if (sacrificePartners < 1 || sacrificePartners > 8) throw new IllegalArgumentException("NoDealerOffline: sacrificePartners must be an integer in [1, 8]");
        }

        @Override public int n() { return n; }

        /** The MAC context: the shares of each key and (for tests and the check only) their sums. */
        @Override public MacContext macContext() {
            List<MacKey> keys = new ArrayList<>();
            for (BigInteger[] shares : keyShares) {
                BigInteger alpha = BigInteger.ZERO;
                for (BigInteger ai : shares) alpha = fadd(alpha, ai);
                keys.add(new MacKey(shares.clone(), alpha));
            }
            return new MacContext(n, keys.get(0).alphaShares(), keys.get(0).alpha(), new ArrayList<>(keys.subList(1, keys.size())));
        }

        private OtChannel channel(int i, int j) {
            String key = i + "->" + j;
            OtChannel ch = channels.get(key);
            if (ch == null) {
                OtRandom otRng = deterministic
                    ? Ot.otRandom(Ot.splitMix64(seed.xor(BigInteger.valueOf(i + 1).multiply(new BigInteger("100000001b3", 16)))
                        .xor(BigInteger.valueOf(j + 1).multiply(new BigInteger("1000000000", 16)))))
                    : Ot.secureOtRandom();
                ch = new OtChannel(otRng);
                channels.put(key, ch);
            }
            return ch;
        }

        private EncShare sampleShare() { return Enc.sampleEnc(gadget, rng); }

        /** Batched Gilboa multiplication: one OT-extension call per ordered party pair for every request. */
        private BigInteger[][] mulBatch(List<Req> reqs) {
            for (Req r : reqs) if (r.x().size() != n || r.y().length != n) throw new IllegalArgumentException("otShareMultiply: wrong length");
            List<List<Piece>> pieces = new ArrayList<>();
            for (Req r : reqs) {
                List<Piece> row = new ArrayList<>();
                for (Object xi : r.x()) {
                    if (xi instanceof EncShare) {
                        EncShare e = (EncShare) xi;
                        row.add(new Piece(e.value(), List.of(new Part(e.bits(), gadget))));
                    } else {
                        BigInteger v = mod((BigInteger) xi);
                        EncShare e = Enc.sampleEnc(gadget, rng);
                        EncShare d = Enc.plainShare(fsub(v, e.value()));
                        row.add(new Piece(v, List.of(new Part(e.bits(), gadget), new Part(d.bits(), Enc.plainGadget()))));
                    }
                }
                pieces.add(row);
            }
            BigInteger[][] z = new BigInteger[reqs.size()][n];
            for (int q = 0; q < reqs.size(); q++) for (int i = 0; i < n; i++) z[q][i] = fmul(pieces.get(q).get(i).value(), reqs.get(q).y()[i]);
            for (int i = 0; i < n; i++) {
                for (int j = 0; j < n; j++) {
                    if (i == j) continue;
                    int rows = 0;
                    for (int q = 0; q < reqs.size(); q++) for (Part part : pieces.get(q).get(i).parts()) rows += part.bits().length;
                    int[] bits = new int[rows];
                    BigInteger[] msg0 = new BigInteger[rows], msg1 = new BigInteger[rows];
                    List<Seg> segs = new ArrayList<>();
                    int at = 0;
                    for (int q = 0; q < reqs.size(); q++) {
                        BigInteger y = mod(reqs.get(q).y()[j]);
                        for (Part part : pieces.get(q).get(i).parts()) {
                            int len = part.bits().length;
                            BigInteger senderSum = BigInteger.ZERO;
                            for (int k = 0; k < len; k++) {
                                BigInteger rho = rng.next();
                                senderSum = fadd(senderSum, rho);
                                bits[at + k] = part.bits()[k];
                                msg0[at + k] = rho;
                                msg1[at + k] = fadd(rho, fmul(part.gad()[k], y));
                            }
                            segs.add(new Seg(q, at, len, senderSum));
                            at += len;
                        }
                    }
                    BigInteger[] received = channel(i, j).extend(bits, msg0, msg1).received();
                    if (log != null) log.add(new OtRecord(i, j, msg0, msg1, received));
                    for (Seg sg : segs) {
                        BigInteger receiverSum = BigInteger.ZERO;
                        for (int k = 0; k < sg.len(); k++) receiverSum = fadd(receiverSum, mod(received[sg.start() + k]));
                        z[sg.q()][i] = fadd(z[sg.q()][i], receiverSum);
                        z[sg.q()][j] = fadd(z[sg.q()][j], fneg(sg.senderSum()));
                    }
                }
            }
            return z;
        }

        /** Additive shares of x*y where party i holds x_i and y_i (all cross terms via OT). */
        public BigInteger[] otShareMultiply(List<Object> x, BigInteger[] y) { return mulBatch(List.of(new Req(x, y)))[0]; }

        private List<Object> keyReq(int l) { return new ArrayList<Object>(Arrays.asList((Object[]) keyEnc[l])); }

        private AuthSV authenticate(BigInteger[] valueShares) {
            List<Req> reqs = new ArrayList<>();
            for (int l = 0; l < keyEnc.length; l++) reqs.add(new Req(keyReq(l), valueShares));
            return toAuth(valueShares, mulBatch(reqs));
        }

        private AuthSV toAuth(BigInteger[] value, BigInteger[][] macs) {
            return new AuthSV(value, macs[0], Arrays.copyOfRange(macs, 1, macs.length));
        }

        private BigInteger[] claimProduct(BigInteger[] implied) {
            BigInteger[] z = implied.clone();
            int idx = productMulCount++;
            if (deviation != null && deviation.productMul() == idx) z[0] = fadd(z[0], deviation.delta());
            claims.add(new ProductClaim(z, implied));
            return z;
        }

        private TripleWithPartners rawTripleWithPartners(int partners) {
            int K = keyEnc.length;
            EncShare[] aEnc = new EncShare[n];
            for (int i = 0; i < n; i++) aEnc[i] = sampleShare();
            BigInteger[] bShares = new BigInteger[n];
            for (int i = 0; i < n; i++) bShares[i] = rng.next();
            EncShare[][] ahEnc = new EncShare[partners][n];
            for (int r = 0; r < partners; r++) for (int i = 0; i < n; i++) ahEnc[r][i] = sampleShare();
            BigInteger[] aVal = new BigInteger[n];
            for (int i = 0; i < n; i++) aVal[i] = aEnc[i].value();
            BigInteger[][] ahVal = new BigInteger[partners][n];
            for (int r = 0; r < partners; r++) for (int i = 0; i < n; i++) ahVal[r][i] = ahEnc[r][i].value();
            List<Req> reqs = new ArrayList<>();
            reqs.add(new Req(new ArrayList<Object>(Arrays.asList((Object[]) aEnc)), bShares));
            for (int r = 0; r < partners; r++) reqs.add(new Req(new ArrayList<Object>(Arrays.asList((Object[]) ahEnc[r])), bShares));
            int macStart = reqs.size();
            for (int l = 0; l < K; l++) {
                reqs.add(new Req(keyReq(l), aVal));
                reqs.add(new Req(keyReq(l), bShares));
                for (int r = 0; r < partners; r++) reqs.add(new Req(keyReq(l), ahVal[r]));
            }
            BigInteger[][] z1 = mulBatch(reqs);
            BigInteger[] cShares = claimProduct(z1[0]);
            BigInteger[][] chShares = new BigInteger[partners][];
            for (int r = 0; r < partners; r++) chShares[r] = claimProduct(z1[1 + r]);
            int per = 2 + partners;
            List<Req> reqs2 = new ArrayList<>();
            for (int l = 0; l < K; l++) {
                reqs2.add(new Req(keyReq(l), cShares));
                for (int r = 0; r < partners; r++) reqs2.add(new Req(keyReq(l), chShares[r]));
            }
            BigInteger[][] z2 = mulBatch(reqs2);
            int per2 = 1 + partners;
            AuthSV b = toAuth(bShares, macOf(z1, macStart, per, 1, K));
            AuthTriple keep = new AuthTriple(toAuth(aVal, macOf(z1, macStart, per, 0, K)), b, toAuth(cShares, macOf(z2, 0, per2, 0, K)));
            List<AuthTriple> parts = new ArrayList<>();
            for (int r = 0; r < partners; r++) {
                parts.add(new AuthTriple(toAuth(ahVal[r], macOf(z1, macStart, per, 2 + r, K)), b, toAuth(chShares[r], macOf(z2, 0, per2, 1 + r, K))));
            }
            return new TripleWithPartners(keep, parts);
        }

        private static BigInteger[][] macOf(BigInteger[][] z, int start, int per, int off, int K) {
            BigInteger[][] out = new BigInteger[K][];
            for (int l = 0; l < K; l++) out[l] = z[start + l * per + off];
            return out;
        }

        private MacCheckAbort attribute(MacCheckAbort abort) {
            TreeSet<Integer> blamed = new TreeSet<>();
            if (log != null) {
                for (OtRecord r : log) {
                    for (int k = 0; k < r.received().length; k++) {
                        BigInteger got = mod(r.received()[k]);
                        if (!got.equals(r.msg0()[k]) && !got.equals(r.msg1()[k])) {
                            blamed.add(r.sender());
                            break;
                        }
                    }
                }
            }
            for (ProductClaim c : claims) {
                for (int i = 0; i < c.claimed().length; i++) if (!c.claimed()[i].equals(c.implied()[i])) blamed.add(i);
            }
            return new OfflineCheatingAbort(abort.getMessage(), new ArrayList<>(blamed));
        }

        /** One authenticated triple, certified by the sacrifice check (or raw when sacrifice is switched off). */
        @Override public AuthTriple genAuthTriple() {
            if (!sacrificeOn) return rawTripleWithPartners(0).keep();
            log = new ArrayList<>();
            claims = new ArrayList<>();
            try {
                TripleWithPartners t = rawTripleWithPartners(sacrificePartners);
                return Spdz.sacrificeVerify(List.of(t), macContext(), rng, List.of()).get(0);
            } catch (MacCheckAbort e) {
                throw attribute(e);
            } finally {
                log = null;
                claims = new ArrayList<>();
            }
        }

        public List<AuthTriple> genAuthTriples(int count) {
            List<AuthTriple> out = new ArrayList<>();
            for (int k = 0; k < count; k++) out.add(genAuthTriple());
            return out;
        }

        /** An authenticated sharing of a value contributed by {@code owner}, MACed by OT under the distributed key. */
        @Override public AuthSV authInput(BigInteger value, int owner) {
            if (owner < 0 || owner >= n) throw new IllegalArgumentException("authInput: owner out of range");
            return authenticate(Sharing.share(mod(value), n, rng));
        }

        /** Verifies that every supplied input's MAC matches its value via a random combination (aborts otherwise). */
        public void checkInputConsistency(List<AuthSV> inputs) {
            if (inputs.isEmpty()) return;
            for (AuthSV inp : inputs) {
                if (inp.value().length != n || inp.mac().length != n) throw new IllegalArgumentException("checkInputConsistency: input party count mismatch");
            }
            MacContext ctx = macContext();
            SpdzEngine engine = new SpdzEngine(ctx, List.of());
            BigInteger[] rShares = new BigInteger[n];
            for (int i = 0; i < n; i++) rShares[i] = rng.next();
            AuthSV w = authenticate(rShares);
            for (AuthSV inp : inputs) {
                BigInteger e = rng.next();
                if (e.signum() == 0) e = BigInteger.ONE;
                w = Spdz.addAuth(w, Spdz.scaleAuth(inp, e));
            }
            engine.open(w, "input-check:w");
            engine.macCheck(rng);
        }
    }

    /** The no-dealer offline provider of {@code n} parties; a non-null seed makes every draw reproducible (tests only). */
    public static NoDealerOffline makeNoDealerOffline(int n, BigInteger seed, NoDealerOptions opts) { return new NoDealerOffline(n, seed, opts); }

    public static NoDealerOffline makeNoDealerOffline(int n, BigInteger seed) { return new NoDealerOffline(n, seed, null); }
}
