package net.atlasauth.pca.mpc.net;

import static net.atlasauth.pca.mpc.Field.PRIME;
import static net.atlasauth.pca.mpc.Field.fadd;
import static net.atlasauth.pca.mpc.Field.fmul;
import static net.atlasauth.pca.mpc.Field.fsub;
import static net.atlasauth.pca.mpc.NetPa.awFlat;
import static net.atlasauth.pca.mpc.NetPa.awParse;
import static net.atlasauth.pca.mpc.NetPa.awWidth;
import static net.atlasauth.pca.mpc.NetPa.paFlat;
import static net.atlasauth.pca.mpc.NetPa.paParse;
import static net.atlasauth.pca.mpc.NetPa.paVerify;
import static net.atlasauth.pca.mpc.NetPa.paWidth;
import static net.atlasauth.pca.mpc.NetPa.wAdd;
import static net.atlasauth.pca.mpc.NetPa.wAddPublic;
import static net.atlasauth.pca.mpc.NetPa.wNeg;
import static net.atlasauth.pca.mpc.NetPa.wScale;
import static net.atlasauth.pca.mpc.NetPa.wSub;
import static net.atlasauth.pca.mpc.NetWire.hx;
import static net.atlasauth.pca.mpc.NetWire.unhxArray;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.IntFunction;
import java.util.regex.Pattern;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.mpc.Compose.ComposedDecision;
import net.atlasauth.pca.mpc.Field.FieldRng;
import net.atlasauth.pca.mpc.Field.FieldSource;
import net.atlasauth.pca.mpc.Field.SecureFieldRng;
import net.atlasauth.pca.mpc.NetCodec;
import net.atlasauth.pca.mpc.NetForensics;
import net.atlasauth.pca.mpc.NetForensics.AuditResult;
import net.atlasauth.pca.mpc.NetForensics.SlotDisclosure;
import net.atlasauth.pca.mpc.NetPa.AW;
import net.atlasauth.pca.mpc.NetPa.PA;
import net.atlasauth.pca.mpc.NetPa.PaEnv;
import net.atlasauth.pca.mpc.NetWire;
import net.atlasauth.pca.mpc.NetWire.NetAbort;
import net.atlasauth.pca.mpc.Party.DecisionVector;
import net.atlasauth.pca.mpc.Spdz;
import net.atlasauth.pca.mpc.Spdz.AuthSV;
import net.atlasauth.pca.mpc.Spdz.AuthTriple;
import net.atlasauth.pca.mpc.Spdz.DealerFault;
import net.atlasauth.pca.mpc.Spdz.MacContext;
import net.atlasauth.pca.mpc.Spdz.MacKey;
import net.atlasauth.pca.mpc.Spdz.TripleWithPartners;
import net.atlasauth.pca.mpc.Thermometer;

/**
 * The DISTRIBUTED malicious-with-abort (SPDZ-style) composition protocol: same circuit and semantics as the in-process runner
 * (allow = AND, t = MAX, r = MAX via thermometers, authenticated Beaver multiplication, batched MAC-check before any output),
 * but each party is its own node holding only its own shares and every opening is a message over the TLS {@link Mesh}.
 * Rounds: prep, coin1-*, sac-rho, sac-tau, inputs (or in-check), mul0.., out, the pairwise tag rounds (dealer mode), coin-c/o,
 * sig-c/o, digest, and on a failed MAC-check a blame round. No output is decoded until the MAC-check and the transcript echo pass.
 *
 * Offline modes: {@code trusted-dealer} (a separate node that knows every share and key; a dealer that gives a wrong triple is
 * detected by the sacrifice, one that deals inconsistent MACs is named by the blame round) and {@code no-dealer}
 * (the parties derive everything from OT). In both modes shares are pairwise-authenticated so an online lie is attributable.
 * There is no security proof; the echo is a hash exchange, not Byzantine agreement; the dealer is trusted for privacy.
 */
public final class Protocol {
    private Protocol() {}

    public static final int T_M = 3;
    static final int DEFAULT_Q = 100;
    private static final int PREP_CHUNK = 30_000;
    private static final Pattern HEX64 = Pattern.compile("^[0-9a-f]{64}$");

    public static int chainCount(int Q) { return 1 + T_M + Q; }

    /** Thrown by the test-only {@code silent} behaviour; the host then idles with its sockets open. */
    public static final class SilentParty extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public SilentParty() { super("silent"); }
    }

    /** Thrown by the test-only {@code crash} behaviour; the host closes the node abruptly. */
    public static final class CrashParty extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public CrashParty() { super("crash"); }
    }

    /** Test-only protocol-level misbehaviour (kind: open-lie, mac-lie, bad-tag, sigma-lie, offline-lie, ot-u-lie, ot-proof-lie, equivocate, bad-coin-open, bad-sigma-open, short-array, noncanonical, crash, silent). */
    public record Behavior(String kind, String round) {}

    public record RoundStat(String rd, double ms, long bytesOut, long bytesIn) {}

    public record PartyResult(int id, int n, int Q, ComposedDecision composed, List<RoundStat> rounds, String transcriptDigest, double wallMs, int multiplications,
        int opens, String offlineMode, int macKeys, int sacrificedTriples, int sacrificePartners, boolean identifiableAbort) {}

    /** What an offline-phase implementation receives from the online driver. */
    public record OfflineCtx(Mesh mesh, int id, int n, int C, int keys, int partners, String sessionId, DecisionVector input, int Q, Behavior behavior, Exchanger io,
        Consumer<String> crashIf) {}

    /** The no-dealer offline phase: produces this party's {@link Prep}. */
    public interface OfflineRunner { Prep run(OfflineCtx ctx); }

    public static final class DealerConfig {
        /** Required true: the dealer sees every share and MAC key. */
        public boolean insecureTrustedDealer;
        public int n;
        public Integer Q;
        public Mesh mesh;
        /** Deterministic stream for reproducible tests; null means the CSPRNG. */
        public BigInteger seed;
        /** TEST ONLY: a LYING dealer that authenticates a wrong product. */
        public DealerFault fault;
        /** TEST ONLY: a dealer that gives party 0 a wrong MAC share for this input mask number. */
        public Integer macFaultAtInput;
    }

    public static final class PartyConfig {
        public int id;
        public int n;
        public Integer Q;
        public DecisionVector input;
        public Mesh mesh;
        /** Node id of the dealer (default n). */
        public Integer dealerId;
        /** "no-dealer" (default) or "trusted-dealer" (which also needs insecureTrustedDealer). */
        public String offline = "no-dealer";
        public boolean insecureTrustedDealer;
        public Behavior behavior;
        public boolean unsafeTestHooks;
        public String sessionId;
        public Integer forensicDeadlineMs;
        /** The no-dealer offline phase; null selects the default implementation. */
        public OfflineRunner offlineRunner;
    }

    private static int intOf(Object o) {
        if (!(o instanceof Json.Num)) return Integer.MIN_VALUE;
        try {
            double d = Double.parseDouble(o.toString());
            return d == Math.rint(d) && Math.abs(d) < 1e9 ? (int) d : Integer.MIN_VALUE;
        } catch (NumberFormatException e) {
            return Integer.MIN_VALUE;
        }
    }

    private static int[] prepLayout(int n, int C, int keys, int partners, boolean tagged) {
        int aw = awWidth(n, keys, tagged);
        int triples = (n - 1) * C;
        int inputs = n * C;
        int nums = (tagged ? 1 : 0) + keys * paWidth(n, tagged) + triples * NetCodec.sharingsPerTriple(partners) * aw + inputs * aw + C;
        return new int[] {nums, triples, inputs};
    }

    // ---------------------------------------------------------------------------------------------- dealer

    private static PA[] dealPA(BigInteger[] x, BigInteger[] deltas, FieldSource rng) {
        int n = x.length;
        BigInteger[][] K = new BigInteger[n][n];
        for (int i = 0; i < n; i++) for (int j = 0; j < n; j++) K[i][j] = i == j ? BigInteger.ZERO : rng.next();
        PA[] out = new PA[n];
        for (int p = 0; p < n; p++) {
            BigInteger[] tag = new BigInteger[n], key = new BigInteger[n];
            for (int j = 0; j < n; j++) {
                tag[j] = j == p ? BigInteger.ZERO : fadd(K[p][j], fmul(deltas[j], x[p]));
                key[j] = j == p ? BigInteger.ZERO : K[j][p];
            }
            out[p] = new PA(x[p], tag, key);
        }
        return out;
    }

    private static AW[] dealAW(AuthSV sv, BigInteger[] deltas, FieldSource rng) {
        int n = sv.value().length;
        List<BigInteger[]> comps = new ArrayList<>();
        comps.add(sv.value());
        comps.add(sv.mac());
        comps.addAll(Arrays.asList(sv.extraMac()));
        List<PA[]> dealt = new ArrayList<>();
        for (BigInteger[] c : comps) dealt.add(dealPA(c, deltas, rng));
        AW[] out = new AW[n];
        for (int p = 0; p < n; p++) {
            PA[] m = new PA[dealt.size() - 1];
            for (int l = 1; l < dealt.size(); l++) m[l - 1] = dealt.get(l)[p];
            out[p] = new AW(dealt.get(0)[p], m);
        }
        return out;
    }

    /**
     * The TRUSTED DEALER role: samples the MAC keys, verification keys, sacrifice-certified authenticated triples and input
     * masks, and ships each party only its own slice. It never sees an input bit, but it knows every key and share.
     */
    public static void runDealer(DealerConfig cfg) {
        int n = cfg.n;
        Mesh mesh = cfg.mesh;
        if (!cfg.insecureTrustedDealer) throw new IllegalArgumentException("runDealer requires insecureTrustedDealer (a dealer sees every share and MAC key; the default offline phase has no dealer)");
        int Q = cfg.Q != null ? cfg.Q : DEFAULT_Q;
        FieldSource rng = cfg.seed != null ? new FieldRng(cfg.seed) : new SecureFieldRng();
        int C = chainCount(Q);
        MacContext ctx = Spdz.setupMac(n, rng, Spdz.MAC_KEYS);
        List<MacKey> keys = Spdz.macKeys(ctx);
        BigInteger[] deltas = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            BigInteger d = rng.next();
            while (d.signum() == 0) d = rng.next();
            deltas[i] = d;
        }
        List<List<BigInteger>> perParty = new ArrayList<>();
        for (int p = 0; p < n; p++) {
            perParty.add(new ArrayList<>());
            perParty.get(p).add(deltas[p]);
        }
        List<PA[]> alphaPA = new ArrayList<>();
        for (MacKey k : keys) alphaPA.add(dealPA(k.alphaShares(), deltas, rng));
        for (int p = 0; p < n; p++) for (PA[] a : alphaPA) perParty.get(p).addAll(paFlat(a[p], p, n, true));

        int nTriples = (n - 1) * C;
        for (int t = 0; t < nTriples; t++) {
            TripleWithPartners tr = Spdz.genTripleWithPartners(ctx, rng, Spdz.SACRIFICE_PARTNERS, cfg.fault);
            List<AuthSV> sharings = new ArrayList<>(List.of(tr.keep().a(), tr.keep().b(), tr.keep().c()));
            for (AuthTriple q : tr.partners()) {
                sharings.add(q.a());
                sharings.add(q.c());
            }
            for (AuthSV sv : sharings) {
                AW[] aws = dealAW(sv, deltas, rng);
                for (int p = 0; p < n; p++) perParty.get(p).addAll(awFlat(aws[p], p, n, true));
            }
        }
        List<List<BigInteger>> masksByOwner = new ArrayList<>();
        for (int p = 0; p < n; p++) masksByOwner.add(new ArrayList<>());
        for (int q = 0; q < n * C; q++) {
            int owner = q / C;
            BigInteger r = rng.next();
            masksByOwner.get(owner).add(r);
            AuthSV sv = Spdz.authShare(r, ctx, rng);
            if (cfg.macFaultAtInput != null && cfg.macFaultAtInput == q) sv.mac()[0] = fadd(sv.mac()[0], BigInteger.ONE);
            AW[] aws = dealAW(sv, deltas, rng);
            for (int p = 0; p < n; p++) perParty.get(p).addAll(awFlat(aws[p], p, n, true));
        }
        for (int p = 0; p < n; p++) perParty.get(p).addAll(masksByOwner.get(p));

        for (int p = 0; p < n; p++) {
            List<String> nums = new ArrayList<>();
            for (BigInteger b : perParty.get(p)) nums.add(hx(b));
            int chunks = Math.max(1, (nums.size() + PREP_CHUNK - 1) / PREP_CHUNK);
            Map<String, Object> first = new LinkedHashMap<>();
            first.put("total", nums.size());
            first.put("chunks", chunks);
            first.put("nums", new ArrayList<Object>(nums.subList(0, Math.min(PREP_CHUNK, nums.size()))));
            mesh.send(p, "prep", first);
            for (int c = 1; c < chunks; c++) mesh.send(p, "prep." + c, new ArrayList<Object>(nums.subList(c * PREP_CHUNK, Math.min((c + 1) * PREP_CHUNK, nums.size()))));
        }
        mesh.finish();
    }

    // ---------------------------------------------------------------------------------------------- party

    private static byte[] sha(Object... parts) {
        try {
            MessageDigest h = MessageDigest.getInstance("SHA-256");
            for (Object p : parts) {
                h.update(p instanceof byte[] ? (byte[]) p : Json.utf8(((String) p)));
                h.update((byte) 0);
            }
            return h.digest();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hex(byte[] b) { return HexFormat.of().formatHex(b); }

    /** Uniform non-zero field element {@code j} of the public challenge stream {@code label} derived from {@code seed}. */
    static BigInteger challenge(byte[] seed, String label, int j) {
        for (int ctr = 0;; ctr++) {
            byte[] h = sha("chal", seed, label + ":" + j + ":" + ctr);
            long x = ByteBuffer.wrap(h).getLong(0) & ((1L << 61) - 1);
            if (x != 0 && x != (1L << 61) - 1) return BigInteger.valueOf(x);
        }
    }

    private record Opened(BigInteger val, PA[] mac) {}

    private record Blame(BigInteger[] g, BigInteger[] gt, BigInteger[] a, BigInteger[] at) {}

    public static PartyResult runParty(PartyConfig cfg) { return new PartyRun(cfg).run(); }

    private static final class PartyRun implements Exchanger {
        final PartyConfig cfg;
        final int id, n, Q, dealerId, C, K, P;
        final Mesh mesh;
        final String sessionId;
        final String offlineMode;
        final Behavior beh;
        final long t0 = System.nanoTime();
        final List<RoundStat> rounds = new ArrayList<>();
        final ByteArrayOutputStream transcript = new ByteArrayOutputStream();
        final List<Integer> others = new ArrayList<>();
        final List<Opened> opened = new ArrayList<>();
        Prep prep;
        PaEnv env;

        PartyRun(PartyConfig cfg) {
            this.cfg = cfg;
            this.id = cfg.id;
            this.n = cfg.n;
            this.mesh = cfg.mesh;
            this.sessionId = cfg.sessionId;
            this.Q = cfg.Q != null ? cfg.Q : DEFAULT_Q;
            this.dealerId = cfg.dealerId != null ? cfg.dealerId : cfg.n;
            this.offlineMode = cfg.offline == null ? "no-dealer" : cfg.offline;
            this.C = chainCount(Q);
            this.K = Spdz.MAC_KEYS;
            this.P = Spdz.SACRIFICE_PARTNERS;
            this.beh = cfg.behavior;
            for (int i = 0; i < n; i++) if (i != id) others.add(i);
        }

        long[] totals() {
            long o = 0, i = 0;
            for (Mesh.LinkStats s : mesh.stats()) {
                o += s.appBytesOut();
                i += s.appBytesIn();
            }
            return new long[] {o, i};
        }

        void crashIf(String rd) {
            if (beh != null && rd.equals(beh.round())) {
                if ("crash".equals(beh.kind())) throw new CrashParty();
                if ("silent".equals(beh.kind())) throw new SilentParty();
            }
        }

        boolean at(String kind, String rd) { return beh != null && kind.equals(beh.kind()) && rd.equals(beh.round()); }

        @Override public RuntimeException bad(int p, String what) { return new NetAbort("malformed", p, id, what); }

        NetAbort abort(NetAbort e) {
            mesh.fail(e, null);
            return e;
        }

        BigInteger[] arr(int p, Object raw, int len) {
            BigInteger[] r = unhxArray(raw, len);
            if (r == null) throw (NetAbort) bad(p, "expected " + len + " canonical field elements");
            return r;
        }

        @Override public <T> Map<Integer, T> exchange(String rd, IntFunction<Object> mine, BiFunction<Integer, Object, T> parse, Long timeoutMs) {
            return exchange(rd, mine, parse, null, false, timeoutMs);
        }

        /** One all-to-all round; {@code hashed = false} keeps a round (peer-specific tags, forensics) out of the echoed transcript. */
        <T> Map<Integer, T> exchange(String rd, IntFunction<Object> mine, BiFunction<Integer, Object, T> parse, Object common, boolean hashed, Long timeoutMs) {
            crashIf(rd);
            long[] a = totals();
            long s = System.nanoTime();
            for (int p : others) mesh.send(p, rd, mine.apply(p));
            Map<Integer, Object> raw = mesh.collect(rd, others, timeoutMs);
            Map<Integer, T> parsed = new TreeMap<>();
            for (int p : others) {
                try {
                    parsed.put(p, parse.apply(p, raw.get(p)));
                } catch (NetAbort e) {
                    mesh.fail(e, null);
                    throw e;
                } catch (RuntimeException e) {
                    NetAbort ne = new NetAbort("malformed", p, id, "round '" + rd + "': " + e.getMessage());
                    mesh.fail(ne, null);
                    throw ne;
                }
            }
            if (hashed) {
                // transcript: party order, canonical JSON of what each party broadcast in this round
                byte[] rb = Json.utf8(rd);
                transcript.write(rb, 0, rb.length);
                for (int p = 0; p < n; p++) {
                    byte[] pb = Json.utf8(("|" + p + ":" + NetWire.stringify(p == id ? common : raw.get(p))));
                    transcript.write(pb, 0, pb.length);
                }
            }
            long[] b = totals();
            rounds.add(new RoundStat(rd, (System.nanoTime() - s) / 1e6, b[0] - a[0], b[1] - a[1]));
            return parsed;
        }

        // ---- trusted-dealer prep ----
        Prep receiveDealerPrep() {
            int[] lay = prepLayout(n, C, K, P, true);
            Object firstRaw = mesh.recv(dealerId, "prep");
            List<BigInteger> nums = new ArrayList<>();
            try {
                Map<?, ?> first = firstRaw instanceof Map ? (Map<?, ?>) firstRaw : null;
                if (first == null || intOf(first.get("total")) != lay[0]) throw (NetAbort) bad(dealerId, "bad prep size");
                int chunks = intOf(first.get("chunks"));
                if (chunks != Math.max(1, (lay[0] + PREP_CHUNK - 1) / PREP_CHUNK)) throw (NetAbort) bad(dealerId, "bad prep chunk count");
                nums.addAll(take(first.get("nums"), Math.min(PREP_CHUNK, lay[0])));
                for (int c = 1; c < chunks; c++) {
                    Object part = mesh.recv(dealerId, "prep." + c);
                    nums.addAll(take(part, Math.min(PREP_CHUNK, lay[0] - c * PREP_CHUNK)));
                }
            } catch (NetAbort e) {
                throw abort(e);
            } catch (RuntimeException e) {
                throw abort(new NetAbort("malformed", dealerId, id, String.valueOf(e.getMessage())));
            }
            int o = 0;
            BigInteger delta = nums.get(o++);
            if (delta.signum() == 0) throw abort(new NetAbort("dealer", dealerId, id, "the dealer gave me a zero verification key"));
            int w = paWidth(n, true);
            PA[] alpha = new PA[K];
            for (int l = 0; l < K; l++) {
                alpha[l] = paParse(nums, o, id, n, true);
                o += w;
            }
            int aw = awWidth(n, K, true);
            int spt = NetCodec.sharingsPerTriple(P);
            AW[][] triples = new AW[lay[1]][];
            for (int t = 0; t < lay[1]; t++) {
                AW[] sh = new AW[spt];
                for (int s = 0; s < spt; s++) {
                    sh[s] = awParse(nums, o, id, n, K, true);
                    o += aw;
                }
                triples[t] = sh;
            }
            AW[] inputs = new AW[lay[2]];
            for (int q = 0; q < lay[2]; q++) {
                inputs[q] = awParse(nums, o, id, n, K, true);
                o += aw;
            }
            BigInteger[] myPlain = nums.subList(o, o + C).toArray(new BigInteger[0]);
            return new Prep("trusted-dealer", true, delta, alpha, triples, inputs, myPlain, null, null);
        }

        List<BigInteger> take(Object raw, int len) {
            BigInteger[] r = unhxArray(raw, len);
            if (r == null) throw (NetAbort) bad(dealerId, "bad prep numbers");
            return Arrays.asList(r);
        }

        AW addPub(AW x, BigInteger c) { return wAddPublic(env, x, c, prep.alpha); }

        AW not(AW x) { return addPub(wNeg(x), BigInteger.ONE); }

        /** Open authenticated values: broadcast value shares, verify pairwise tags (dealer mode), record for the MAC-check. */
        BigInteger[] openMany(String rd, AW[] ws) {
            BigInteger[] sendVals = new BigInteger[ws.length];
            PA[][] macs = new PA[ws.length][];
            for (int i = 0; i < ws.length; i++) {
                sendVals[i] = ws[i].v().x();
                macs[i] = ws[i].m();
            }
            if (beh != null && rd.equals(beh.round())) {
                if ("open-lie".equals(beh.kind())) sendVals[0] = fadd(sendVals[0], BigInteger.ONE);
                if ("mac-lie".equals(beh.kind())) {
                    PA[] m0 = macs[0].clone();
                    m0[0] = new PA(fadd(m0[0].x(), BigInteger.ONE), m0[0].tag(), m0[0].key());
                    macs[0] = m0;
                }
            }
            final List<Object> common = new ArrayList<>();
            for (BigInteger v : sendVals) common.add(hx(v));
            IntFunction<Object> mineFn = peer -> {
                if (at("equivocate", rd) && peer == others.get(0)) {
                    List<Object> c = new ArrayList<>(common);
                    c.set(0, hx(fadd(new BigInteger((String) common.get(0), 16), BigInteger.ONE)));
                    return c;
                }
                if (at("short-array", rd)) return new ArrayList<>(common.subList(1, common.size()));
                if (at("noncanonical", rd)) {
                    List<Object> c = new ArrayList<>(common);
                    c.set(0, hx(PRIME));
                    return c;
                }
                return common;
            };
            Map<Integer, BigInteger[]> got = exchange(rd, mineFn, (p, raw) -> arr(p, raw, ws.length), common, true, null);
            if (prep.tagged) {
                // pairwise tags: peer-specific, so a separate un-echoed round; each receiver verifies at once
                IntFunction<Object> tagMsg = peer -> {
                    List<Object> t = new ArrayList<>();
                    for (int i = 0; i < ws.length; i++) {
                        BigInteger tag = ws[i].v().tag()[peer];
                        t.add(hx(at("bad-tag", rd) && i == 0 ? fadd(tag, BigInteger.ONE) : tag));
                    }
                    return t;
                };
                Map<Integer, BigInteger[]> tags = exchange(rd + ".t", tagMsg, (p, raw) -> arr(p, raw, ws.length), null, false, null);
                for (int p : others) {
                    for (int i = 0; i < ws.length; i++) {
                        if (!paVerify(env, ws[i].v(), p, got.get(p)[i], tags.get(p)[i])) {
                            throw abort(new NetAbort("mac-check", p, id,
                                "pairwise MAC on party " + p + "'s opened share failed in round '" + rd + "' (index " + i + "): the share or its tag is not what the dealer issued"));
                        }
                    }
                }
            }
            BigInteger[] out = new BigInteger[ws.length];
            for (int i = 0; i < ws.length; i++) {
                BigInteger sum = sendVals[i];
                for (int p : others) sum = fadd(sum, got.get(p)[i]);
                out[i] = sum;
                opened.add(new Opened(sum, macs[i]));
            }
            return out;
        }

        /** Commit / open of a random seed, giving a joint public seed. */
        byte[] coin(String label, boolean tamperOpen) {
            byte[] mySeed = new byte[32];
            new SecureRandom().nextBytes(mySeed);
            String seedCommit = hex(sha("seed", sessionId, label, String.valueOf(id), mySeed));
            Map<Integer, String> seedCommits = exchange(label + "-c", p -> seedCommit, (p, raw) -> {
                if (raw instanceof String && HEX64.matcher((String) raw).matches()) return (String) raw;
                throw bad(p, "bad commitment");
            }, seedCommit, true, null);
            IntFunction<Object> openMsg = p -> {
                if (tamperOpen && beh != null && "bad-coin-open".equals(beh.kind())) {
                    byte[] r = new byte[32];
                    new SecureRandom().nextBytes(r);
                    return hex(r);
                }
                return hex(mySeed);
            };
            Map<Integer, byte[]> seeds = exchange(label + "-o", openMsg, (p, raw) -> {
                if (!(raw instanceof String) || !HEX64.matcher((String) raw).matches()) throw bad(p, "bad seed");
                byte[] sd = HexFormat.of().parseHex((String) raw);
                if (!hex(sha("seed", sessionId, label, String.valueOf(p), sd)).equals(seedCommits.get(p))) {
                    throw new NetAbort("commitment", p, id, "party " + p + " opened a coin seed that does not match its commitment");
                }
                return sd;
            }, hex(mySeed), true, null);
            Object[] parts = new Object[3 + n];
            parts[0] = "joint";
            parts[1] = sessionId;
            parts[2] = label;
            for (int p = 0; p < n; p++) parts[3 + p] = p == id ? mySeed : seeds.get(p);
            return sha(parts);
        }

        String sigCommit(int p, BigInteger[] s, byte[] nonce) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < s.length; i++) sb.append(i == 0 ? "" : ",").append(hx(s[i]));
            return hex(sha("sigma", sessionId, String.valueOf(p), sb.toString(), nonce));
        }

        BigInteger bitOf(BigInteger x) { return x.equals(BigInteger.ONE) ? BigInteger.ONE : BigInteger.ZERO; }

        // inputs state
        BigInteger[] masked;
        Map<Integer, BigInteger[]> gotMasked;

        AW bitShare(int owner, int k) {
            if (prep.mode.equals("trusted-dealer")) {
                BigInteger pub = owner == id ? masked[k] : gotMasked.get(owner)[k];
                return addPub(prep.inputs[owner * C + k], pub);
            }
            return prep.inputs[owner * C + k];
        }

        PartyResult run() {
            if (offlineMode.equals("trusted-dealer") && !cfg.insecureTrustedDealer) {
                throw new NetAbort("local", null, id, "offline 'trusted-dealer' requires insecureTrustedDealer (the dealer sees every share and key); the default is 'no-dealer'");
            }
            if (beh != null && !cfg.unsafeTestHooks) throw new NetAbort("local", null, id, "the behavior test hook requires unsafeTestHooks (test-only)");
            if (n < 1) throw new NetAbort("local", null, id, "n must be >= 1");
            DecisionVector v = cfg.input;
            if (v == null || (v.allow() != 0 && v.allow() != 1) || v.t() < 1 || v.t() > 3 || v.rQuant() < 0 || v.rQuant() > Q) {
                throw new NetAbort("local", null, id, "invalid decision vector");
            }

            // ---- offline phase ----
            crashIf("prep");
            long prepStart = System.nanoTime();
            long[] before = totals();
            if (offlineMode.equals("trusted-dealer")) {
                prep = receiveDealerPrep();
            } else {
                OfflineRunner runner = cfg.offlineRunner != null ? cfg.offlineRunner : OfflineNet::run;
                prep = runner.run(new OfflineCtx(mesh, id, n, C, K, P, sessionId, v, Q, beh, this, this::crashIf));
            }
            long[] afterPrep = totals();
            rounds.add(new RoundStat("prep", (System.nanoTime() - prepStart) / 1e6, afterPrep[0] - before[0], afterPrep[1] - before[1]));
            env = new PaEnv(id, n, prep.delta, prep.tagged);

            // ---- sacrifice: certify every triple against its partners before it is used ----
            int nT = prep.triples.length;
            if (nT > 0) sacrifice(nT);

            // ---- inputs ----
            int[] therm = Thermometer.thermometerEncode(v.t(), T_M);
            int[] rtherm = Thermometer.thermometerEncode(v.rQuant(), Q);
            BigInteger[] myBits = new BigInteger[C];
            myBits[0] = BigInteger.valueOf(v.allow());
            for (int i = 0; i < T_M; i++) myBits[1 + i] = BigInteger.valueOf(therm[i]);
            for (int i = 0; i < Q; i++) myBits[1 + T_M + i] = BigInteger.valueOf(rtherm[i]);
            if (prep.mode.equals("trusted-dealer")) {
                masked = new BigInteger[C];
                List<Object> maskedMsg = new ArrayList<>();
                for (int k = 0; k < C; k++) {
                    masked[k] = fsub(myBits[k], prep.myPlain[k]);
                    maskedMsg.add(hx(masked[k]));
                }
                gotMasked = exchange("inputs", p -> maskedMsg, (p, raw) -> arr(p, raw, C), maskedMsg, true, null);
            } else {
                // No-dealer: inputs are already authenticated sharings; MASCOT input-consistency check (joins the batched MAC-check).
                byte[] jointIn = coin("coin-in", false);
                AW w = prep.checkMask;
                for (int q = 0; q < n * C; q++) w = wAdd(w, wScale(prep.inputs[q], challenge(jointIn, "in", q)));
                openMany("in-check", new AW[] {w});
            }

            // ---- chains: acc_c over owners; allow uses AND, the others OR (= NOT AND NOT) ----
            AW[] acc = new AW[C];
            for (int c = 0; c < C; c++) {
                AW b0 = bitShare(0, c);
                acc[c] = c != 0 ? not(b0) : b0;
            }
            int mults = 0;
            for (int s = 1; s < n; s++) {
                AW[][] trs = new AW[C][];
                for (int c = 0; c < C; c++) trs[c] = prep.triples[(s - 1) * C + c];
                AW[] ds = new AW[C], es = new AW[C];
                for (int c = 0; c < C; c++) {
                    AW b = bitShare(s, c);
                    AW y = c != 0 ? not(b) : b;
                    ds[c] = wSub(acc[c], trs[c][0]);
                    es[c] = wSub(y, trs[c][1]);
                }
                AW[] both = new AW[2 * C];
                System.arraycopy(ds, 0, both, 0, C);
                System.arraycopy(es, 0, both, C, C);
                BigInteger[] pub = openMany("mul" + (s - 1), both);
                AW[] next = new AW[C];
                for (int c = 0; c < C; c++) {
                    BigInteger d = pub[c], e = pub[C + c];
                    AW z = wAdd(trs[c][2], wAdd(wScale(trs[c][1], d), wScale(trs[c][0], e)));
                    next[c] = addPub(z, fmul(d, e));
                }
                acc = next;
                mults += C;
            }

            // ---- outputs: allow as-is; or-chains are NOT of the product ----
            AW[] outShares = new AW[C];
            for (int c = 0; c < C; c++) outShares[c] = c != 0 ? not(acc[c]) : acc[c];
            BigInteger[] outVals = openMany("out", outShares);

            // ---- MAC-check ----
            byte[] joint = coin("coin", true);
            BigInteger[] aPub = new BigInteger[K], Gamma = new BigInteger[K], sigma = new BigInteger[K];
            for (int l = 0; l < K; l++) {
                BigInteger a = BigInteger.ZERO, g = BigInteger.ZERO;
                for (int j = 0; j < opened.size(); j++) {
                    BigInteger ch = challenge(joint, "mac" + l, j);
                    a = fadd(a, fmul(ch, opened.get(j).val()));
                    g = fadd(g, fmul(ch, opened.get(j).mac()[l].x()));
                }
                aPub[l] = a;
                Gamma[l] = g;
                sigma[l] = fsub(g, fmul(prep.alpha[l].x(), a));
            }
            byte[] sigNonce = new byte[32];
            new SecureRandom().nextBytes(sigNonce);
            BigInteger[] sigmaSent = sigma.clone();
            if (beh != null && "sigma-lie".equals(beh.kind())) sigmaSent[0] = fadd(sigmaSent[0], BigInteger.ONE);
            String mySigCommit = sigCommit(id, sigmaSent, sigNonce);
            Map<Integer, String> sigCommits = exchange("sig-c", p -> mySigCommit, (p, raw) -> {
                if (raw instanceof String && HEX64.matcher((String) raw).matches()) return (String) raw;
                throw bad(p, "bad commitment");
            }, mySigCommit, true, null);
            Map<String, Object> mySigOpen = new LinkedHashMap<>();
            mySigOpen.put("s", hexList(sigmaSent));
            mySigOpen.put("nonce", hex(sigNonce));
            Map<Integer, BigInteger[]> sigOpens = exchange("sig-o", p -> {
                if (beh != null && "bad-sigma-open".equals(beh.kind())) {
                    BigInteger[] s2 = sigmaSent.clone();
                    s2[0] = fadd(s2[0], BigInteger.ONE);
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("s", hexList(s2));
                    m.put("nonce", mySigOpen.get("nonce"));
                    return m;
                }
                return mySigOpen;
            }, (p, raw) -> {
                Map<?, ?> o = raw instanceof Map ? (Map<?, ?>) raw : null;
                BigInteger[] sv = o == null ? null : unhxArray(o.get("s"), K);
                if (sv == null || !(o.get("nonce") instanceof String) || !HEX64.matcher((String) o.get("nonce")).matches()) throw bad(p, "bad sigma opening");
                if (!sigCommit(p, sv, HexFormat.of().parseHex((String) o.get("nonce"))).equals(sigCommits.get(p))) {
                    throw new NetAbort("commitment", p, id, "party " + p + " opened a MAC residual that does not match its commitment");
                }
                return sv;
            }, mySigOpen, true, null);
            boolean macFailed = false;
            for (int l = 0; l < K; l++) {
                BigInteger r = sigmaSent[l];
                for (int p : others) r = fadd(r, sigOpens.get(p)[l]);
                if (r.signum() != 0) macFailed = true;
            }

            // ---- transcript echo: everyone must have seen the same broadcasts ----
            String digest = hex(sha256(transcript.toByteArray()));
            Map<Integer, String> digests = exchange("digest", p -> digest, (p, raw) -> {
                if (raw instanceof String && HEX64.matcher((String) raw).matches()) return (String) raw;
                throw bad(p, "bad digest");
            }, digest, true, null);
            for (int p : others) {
                if (!digest.equals(digests.get(p))) throw abort(new NetAbort("equivocation", p, id, "transcript digest of party " + p + " differs from mine (a broadcast was inconsistent)"));
            }

            if (macFailed) blame(aPub, Gamma, sigOpens, joint);

            // ---- only now decode ----
            int[] tBits = new int[T_M], rBits = new int[Q];
            for (int i = 0; i < T_M; i++) tBits[i] = bitOf(outVals[1 + i]).intValue();
            for (int i = 0; i < Q; i++) rBits[i] = bitOf(outVals[1 + T_M + i]).intValue();
            int allow = bitOf(outVals[0]).intValue();
            ComposedDecision composed = new ComposedDecision(allow, Math.min(3, Math.max(1, Thermometer.thermometerDecode(tBits))), Thermometer.thermometerDecode(rBits));
            mesh.finish();
            return new PartyResult(id, n, Q, composed, rounds, digest, (System.nanoTime() - t0) / 1e6, mults, opened.size(), prep.mode, K, nT, P, prep.tagged);
        }

        static byte[] sha256(byte[] b) {
            try {
                return MessageDigest.getInstance("SHA-256").digest(b);
            } catch (java.security.NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }

        static List<Object> hexList(BigInteger[] xs) {
            List<Object> out = new ArrayList<>();
            for (BigInteger x : xs) out.add(hx(x));
            return out;
        }

        void sacrifice(int nT) {
            byte[] joint1 = coin("coin1", false);
            AW[] rhoW = new AW[nT * P];
            for (int t = 0; t < nT; t++) {
                AW[] tr = prep.triples[t];
                for (int r = 0; r < P; r++) {
                    BigInteger e = challenge(joint1, "sac", t * P + r);
                    rhoW[t * P + r] = wSub(wScale(tr[0], e), tr[3 + 2 * r]);
                }
            }
            BigInteger[] rho = openMany("sac-rho", rhoW);
            AW[] tauW = new AW[nT * P];
            for (int t = 0; t < nT; t++) {
                AW[] tr = prep.triples[t];
                for (int r = 0; r < P; r++) {
                    BigInteger e = challenge(joint1, "sac", t * P + r);
                    tauW[t * P + r] = wSub(wSub(wScale(tr[2], e), tr[3 + 2 * r + 1]), wScale(tr[1], rho[t * P + r]));
                }
            }
            BigInteger[] tau = openMany("sac-tau", tauW);
            int badAt = -1;
            for (int i = 0; i < tau.length; i++) if (tau[i].signum() != 0) { badAt = i; break; }
            if (badAt < 0) return;
            // Dealer-free mode: the triple is discarded, so its OT transcript can be disclosed and audited to name a party that fed a wrong operand.
            Integer attributed = null;
            String note = "";
            Prep.Forensics fx = prep.mode.equals("no-dealer") ? prep.forensics : null;
            if (fx != null) {
                int bt = badAt / P;
                List<SlotDisclosure> mine = fx.disclose().apply(bt);
                // commit first, open only once every commitment is in hand; a late or absent party times out at the shared deadline
                long deadline = cfg.forensicDeadlineMs != null ? cfg.forensicDeadlineMs : NetForensics.DEFAULT_FORENSIC_DEADLINE_MS;
                Map<Integer, List<SlotDisclosure>> got = Forensic.exchangeDisclosures(sessionId, id, n, bt, mine, fx.slots(), fx.rows(), deadline, this);
                Map<Integer, List<SlotDisclosure>> all = new TreeMap<>(got);
                all.put(id, mine);
                AuditResult res = NetForensics.auditDisclosures(all, fx.gadget());
                attributed = NetForensics.blameFrom(id, res);
                note = attributed == null
                    ? " (OT transcript audit: " + res.pairBad().size() + " inconsistent pair(s), no party can be named from this view: a pair failure between two other parties is not evidence against either of them to me)"
                    : " (OT transcript audit names party " + attributed + ")";
            }
            boolean dealer = prep.mode.equals("trusted-dealer");
            Integer blamed = dealer ? Integer.valueOf(dealerId) : (attributed != null ? attributed : (n == 2 ? Integer.valueOf(1 - id) : null));
            throw abort(new NetAbort(dealer ? "dealer" : "mac-check", blamed, id,
                "triple sacrifice FAILED at triple " + (badAt / P) + " (partner " + (badAt % P) + "): c != a*b in the offline material; aborting with no output" + note,
                null, null, "the triple sacrifice failed in dealer-free mode and the OT transcript audit of this party's own view names no one (a failing pair that does not involve me is not evidence I can use, and an accusation is never accepted as evidence)",
                null, null));
        }

        void blame(BigInteger[] aPub, BigInteger[] Gamma, Map<Integer, BigInteger[]> sigOpens, byte[] joint) {
            String msg = "MAC-check FAILED: an opened value or MAC share was inconsistent; aborting with no output";
            if (!prep.tagged) {
                throw abort(new NetAbort("mac-check", n == 2 ? Integer.valueOf(1 - id) : null, id, msg, null, null,
                    "this mode carries no pairwise tags, so a MAC-check failure cannot name a party (only possible with two parties)", null, null));
            }
            // every party opens its combined MAC shares with their pairwise tags; each verifier checks them
            IntFunction<Object> blameMsg = peer -> {
                Map<String, Object> m = new LinkedHashMap<>();
                List<Object> gt = new ArrayList<>(), a = new ArrayList<>(), at = new ArrayList<>();
                for (int l = 0; l < K; l++) {
                    BigInteger g = BigInteger.ZERO;
                    for (int j = 0; j < opened.size(); j++) g = fadd(g, fmul(challenge(joint, "mac" + l, j), opened.get(j).mac()[l].tag()[peer]));
                    gt.add(hx(g));
                    a.add(hx(prep.alpha[l].x()));
                    at.add(hx(prep.alpha[l].tag()[peer]));
                }
                m.put("g", hexList(Gamma));
                m.put("gt", gt);
                m.put("a", a);
                m.put("at", at);
                return m;
            };
            // Abort claims arriving during this round are read in link order (see Mesh.setDeferAborts).
            mesh.setDeferAborts(true);
            Map<Integer, Blame> blames;
            try {
                blames = exchange("blame", blameMsg, (p, raw) -> {
                    Map<?, ?> o = raw instanceof Map ? (Map<?, ?>) raw : Map.of();
                    return new Blame(arr(p, o.get("g"), K), arr(p, o.get("gt"), K), arr(p, o.get("a"), K), arr(p, o.get("at"), K));
                }, null, false, null);
            } finally {
                mesh.setDeferAborts(false);
            }
            for (int p : others) {
                Blame b = blames.get(p);
                for (int l = 0; l < K; l++) {
                    BigInteger keyCombo = BigInteger.ZERO;
                    for (int j = 0; j < opened.size(); j++) keyCombo = fadd(keyCombo, fmul(challenge(joint, "mac" + l, j), opened.get(j).mac()[l].key()[p]));
                    if (!fadd(keyCombo, fmul(env.delta(), b.g()[l])).equals(b.gt()[l])) {
                        throw abort(new NetAbort("mac-check", p, id, msg + " - party " + p + "'s MAC share (key " + l + ") does not match its pairwise tag"));
                    }
                    if (!fadd(prep.alpha[l].key()[p], fmul(env.delta(), b.a()[l])).equals(b.at()[l])) {
                        throw abort(new NetAbort("mac-check", p, id, msg + " - party " + p + "'s key share (key " + l + ") does not match its pairwise tag"));
                    }
                    if (!fsub(b.g()[l], fmul(b.a()[l], aPub[l])).equals(sigOpens.get(p)[l])) {
                        throw abort(new NetAbort("mac-check", p, id, msg + " - party " + p + "'s opened MAC residual (key " + l + ") is not what its authenticated shares give"));
                    }
                }
            }
            // Every other party's data is consistent with its pairwise tags; so is mine: the offline material disagrees.
            if (prep.mode.equals("trusted-dealer")) {
                throw abort(new NetAbort("dealer", dealerId, id, msg + " - every party's shares verify, so the trusted dealer's MACs are inconsistent with its values"));
            }
            throw abort(new NetAbort("mac-check", n == 2 ? Integer.valueOf(1 - id) : null, id,
                msg + " - every party's shares verify under its pairwise tags, so the offline material is inconsistent (a wrong OT operand): not attributable", null, null,
                "every party's shares verify under its pairwise tags, so the fault lies in the offline material, which names no party", null, null));
        }
    }
}
