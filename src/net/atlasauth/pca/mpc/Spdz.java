package net.atlasauth.pca.mpc;

import net.atlasauth.pca.Json;

import static net.atlasauth.pca.mpc.Field.PRIME;
import static net.atlasauth.pca.mpc.Field.fadd;
import static net.atlasauth.pca.mpc.Field.fmul;
import static net.atlasauth.pca.mpc.Field.fneg;
import static net.atlasauth.pca.mpc.Field.fsub;
import static net.atlasauth.pca.mpc.Field.mod;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import net.atlasauth.pca.mpc.Field.FieldSource;

/**
 * SPDZ-style authenticated secret sharing over F_p: the malicious-with-abort (dishonest-majority) layer. A global MAC key
 * alpha is additively shared; every authenticated value carries MAC shares summing to alpha*x under MAC_KEYS independent
 * keys; the batched commit-then-open MAC-check aborts on any deviation, so the result is correct or an abort. The
 * authenticated triples come from a trusted dealer (the explicit trust assumption); the online phase is the real thing.
 */
public final class Spdz {
    private Spdz() {}

    /** One global MAC key, additively shared. {@code alpha} is for dealer preprocessing and tests only. */
    public record MacKey(BigInteger[] alphaShares, BigInteger alpha) {}

    /** The global MAC keys: key 0 is alphaShares/alpha; extraKeys are further independent keys. */
    public record MacContext(int n, BigInteger[] alphaShares, BigInteger alpha, List<MacKey> extraKeys) {}

    /** value shares sum to x, mac shares to alpha*x (key 0), extraMac[l-1] to extraKeys[l-1].alpha*x. */
    public record AuthSV(BigInteger[] value, BigInteger[] mac, BigInteger[][] extraMac) {}

    public record AuthTriple(AuthSV a, AuthSV b, AuthSV c) {}

    public static final int MAC_KEYS = 2;
    public static final int MIN_MAC_SOUNDNESS_BITS = 100;
    public static final int SACRIFICE_PARTNERS = 2;

    public static List<MacKey> macKeys(MacContext ctx) {
        List<MacKey> out = new ArrayList<>();
        out.add(new MacKey(ctx.alphaShares(), ctx.alpha()));
        out.addAll(ctx.extraKeys());
        return out;
    }

    /** keys * (log2 p - 1): the soundness in bits of the batched MAC-check. */
    public static double macSoundnessBits(int keys, BigInteger p) {
        double d = p.doubleValue();
        double l = Math.log(d) / Math.log(2);
        double r = Math.rint(l);
        if (Math.abs(l - r) < 1e-9 && Math.pow(2, r) == d) l = r;
        return keys * (l - 1);
    }

    public static double macSoundnessBits(int keys) { return macSoundnessBits(keys, PRIME); }

    /** Raised when the MAC-check detects an inconsistent opening/MAC: the protocol ABORTS, no output. */
    public static class MacCheckAbort extends RuntimeException {
        public MacCheckAbort(String message) { super(message); }
    }

    public static MacContext setupMac(int n, FieldSource rng, int keys) {
        if (n < 1) throw new IllegalArgumentException("setupMac: n must be a positive integer");
        if (keys < 1 || keys > 16) throw new IllegalArgumentException("setupMac: keys must be an integer in [1, 16]");
        MacKey first = mk(n, rng);
        List<MacKey> extra = new ArrayList<>();
        for (int i = 0; i < keys - 1; i++) extra.add(mk(n, rng));
        return new MacContext(n, first.alphaShares(), first.alpha(), extra);
    }

    public static MacContext setupMac(int n, FieldSource rng) { return setupMac(n, rng, MAC_KEYS); }

    private static MacKey mk(int n, FieldSource rng) {
        BigInteger alpha = rng.next();
        return new MacKey(Sharing.share(alpha, n, rng), alpha);
    }

    public static AuthSV authShare(BigInteger secret, MacContext ctx, FieldSource rng) {
        BigInteger v = mod(secret);
        BigInteger[] value = Sharing.share(v, ctx.n(), rng);
        BigInteger[] mac = Sharing.share(fmul(ctx.alpha(), v), ctx.n(), rng);
        BigInteger[][] extra = new BigInteger[ctx.extraKeys().size()][];
        for (int l = 0; l < extra.length; l++) extra[l] = Sharing.share(fmul(ctx.extraKeys().get(l).alpha(), v), ctx.n(), rng);
        return new AuthSV(value, mac, extra);
    }

    public static AuthSV authConstant(BigInteger c, MacContext ctx) {
        BigInteger v = mod(c);
        BigInteger[] value = new BigInteger[ctx.n()];
        Arrays.fill(value, BigInteger.ZERO);
        value[0] = v;
        BigInteger[] mac = scaleAll(ctx.alphaShares(), v);
        BigInteger[][] extra = new BigInteger[ctx.extraKeys().size()][];
        for (int l = 0; l < extra.length; l++) extra[l] = scaleAll(ctx.extraKeys().get(l).alphaShares(), v);
        return new AuthSV(value, mac, extra);
    }

    private static BigInteger[] scaleAll(BigInteger[] xs, BigInteger c) {
        BigInteger[] o = new BigInteger[xs.length];
        for (int i = 0; i < xs.length; i++) o[i] = fmul(xs[i], c);
        return o;
    }

    private interface Op2 { BigInteger f(BigInteger a, BigInteger b); }

    private static BigInteger[] zip(BigInteger[] x, BigInteger[] y, Op2 f) {
        BigInteger[] o = new BigInteger[x.length];
        for (int i = 0; i < x.length; i++) o[i] = f.f(x[i], y[i]);
        return o;
    }

    private static BigInteger[][] zipMac(BigInteger[][] x, BigInteger[][] y, Op2 f) {
        BigInteger[][] o = new BigInteger[x.length][];
        for (int l = 0; l < x.length; l++) o[l] = zip(x[l], y[l], f);
        return o;
    }

    public static AuthSV addAuth(AuthSV x, AuthSV y) {
        requireSame(x, y);
        return new AuthSV(zip(x.value(), y.value(), Field::fadd), zip(x.mac(), y.mac(), Field::fadd), zipMac(x.extraMac(), y.extraMac(), Field::fadd));
    }

    public static AuthSV subAuth(AuthSV x, AuthSV y) {
        requireSame(x, y);
        return new AuthSV(zip(x.value(), y.value(), Field::fsub), zip(x.mac(), y.mac(), Field::fsub), zipMac(x.extraMac(), y.extraMac(), Field::fsub));
    }

    public static AuthSV negAuth(AuthSV x) {
        BigInteger[][] e = new BigInteger[x.extraMac().length][];
        for (int l = 0; l < e.length; l++) e[l] = negAll(x.extraMac()[l]);
        return new AuthSV(negAll(x.value()), negAll(x.mac()), e);
    }

    private static BigInteger[] negAll(BigInteger[] xs) {
        BigInteger[] o = new BigInteger[xs.length];
        for (int i = 0; i < xs.length; i++) o[i] = fneg(xs[i]);
        return o;
    }

    public static AuthSV scaleAuth(AuthSV x, BigInteger c) {
        BigInteger k = mod(c);
        BigInteger[][] e = new BigInteger[x.extraMac().length][];
        for (int l = 0; l < e.length; l++) e[l] = scaleAll(x.extraMac()[l], k);
        return new AuthSV(scaleAll(x.value(), k), scaleAll(x.mac(), k), e);
    }

    /** x + c for a PUBLIC constant c: c to one party's value share, alpha_i*c to every party's MAC share under every key. */
    public static AuthSV addPublicAuth(AuthSV x, BigInteger c, MacContext ctx) {
        int n = ctx.n();
        if (x.value().length != n || x.mac().length != n || ctx.alphaShares().length != n) {
            throw new IllegalArgumentException("addPublicAuth: shared value and MAC context disagree on the party count");
        }
        if (x.extraMac().length != ctx.extraKeys().size()) throw new IllegalArgumentException("addPublicAuth: shared value and MAC context disagree on the key count");
        BigInteger k = mod(c);
        BigInteger[] value = x.value().clone();
        value[0] = fadd(value[0], k);
        BigInteger[] mac = new BigInteger[n];
        for (int i = 0; i < n; i++) mac[i] = fadd(x.mac()[i], fmul(ctx.alphaShares()[i], k));
        BigInteger[][] extra = new BigInteger[x.extraMac().length][];
        for (int l = 0; l < extra.length; l++) {
            BigInteger[] row = x.extraMac()[l];
            MacKey key = ctx.extraKeys().get(l);
            if (row.length != n || key.alphaShares().length != n) throw new IllegalArgumentException("addPublicAuth: extra MAC party count mismatch");
            extra[l] = new BigInteger[n];
            for (int i = 0; i < n; i++) extra[l][i] = fadd(row[i], fmul(key.alphaShares()[i], k));
        }
        return new AuthSV(value, mac, extra);
    }

    public static AuthSV notBitAuth(AuthSV b, MacContext ctx) { return addPublicAuth(negAuth(b), BigInteger.ONE, ctx); }

    public static AuthTriple genAuthTriple(MacContext ctx, FieldSource rng) {
        BigInteger a = rng.next();
        BigInteger b = rng.next();
        AuthSV as = authShare(a, ctx, rng);
        AuthSV bs = authShare(b, ctx, rng);
        AuthSV cs = authShare(fmul(a, b), ctx, rng);
        return new AuthTriple(as, bs, cs);
    }

    /** A triple to deliver plus its sacrifice partners (every partner shares keep.b). */
    public record TripleWithPartners(AuthTriple keep, List<AuthTriple> partners) {}

    /** TEST-ONLY lying-dealer fault: the dealer authenticates a wrong product. Null entries mean no delta. */
    public record DealerFault(BigInteger keepCDelta, List<BigInteger> partnerCDelta) {}

    public static TripleWithPartners genTripleWithPartners(MacContext ctx, FieldSource rng, int partners, DealerFault fault) {
        if (partners < 1 || partners > 8) throw new IllegalArgumentException("genTripleWithPartners: partners must be in [1, 8]");
        BigInteger a = rng.next();
        BigInteger b = rng.next();
        AuthSV bSV = authShare(b, ctx, rng);
        BigInteger kd = fault != null && fault.keepCDelta() != null ? fault.keepCDelta() : BigInteger.ZERO;
        AuthSV keepA = authShare(a, ctx, rng);
        AuthSV keepC = authShare(fadd(fmul(a, b), kd), ctx, rng);
        AuthTriple keep = new AuthTriple(keepA, bSV, keepC);
        List<AuthTriple> ps = new ArrayList<>();
        for (int r = 0; r < partners; r++) {
            BigInteger ah = rng.next();
            BigInteger pd = fault != null && fault.partnerCDelta() != null && r < fault.partnerCDelta().size() && fault.partnerCDelta().get(r) != null
                ? fault.partnerCDelta().get(r) : BigInteger.ZERO;
            AuthSV pa = authShare(ah, ctx, rng);
            AuthSV pc = authShare(fadd(fmul(ah, b), pd), ctx, rng);
            ps.add(new AuthTriple(pa, bSV, pc));
        }
        return new TripleWithPartners(keep, ps);
    }

    public static TripleWithPartners genTripleWithPartners(MacContext ctx, FieldSource rng) {
        return genTripleWithPartners(ctx, rng, SACRIFICE_PARTNERS, null);
    }

    /** Sacrifice check: certifies the kept triples or throws {@link MacCheckAbort}, emitting nothing. */
    public static List<AuthTriple> sacrificeVerify(List<TripleWithPartners> batch, MacContext ctx, FieldSource rng, List<Deviation> deviations) {
        SpdzEngine engine = new SpdzEngine(ctx, deviations);
        List<BigInteger> taus = new ArrayList<>();
        for (TripleWithPartners t : batch) {
            AuthTriple keep = t.keep();
            if (t.partners().size() < 1) throw new MacCheckAbort("sacrifice: a triple without partners cannot be certified");
            for (AuthTriple sac : t.partners()) {
                if (!Arrays.equals(sac.b().value(), keep.b().value())) throw new MacCheckAbort("sacrifice: partner does not share b with the triple");
                BigInteger e = rng.next();
                if (e.signum() == 0) e = BigInteger.ONE;
                BigInteger rho = engine.open(subAuth(scaleAuth(keep.a(), e), sac.a()), "sacrifice:rho");
                AuthSV tau = subAuth(scaleAuth(keep.c(), e), sac.c());
                tau = subAuth(tau, scaleAuth(keep.b(), rho));
                taus.add(engine.open(tau, "sacrifice:tau"));
            }
        }
        engine.macCheck(rng);
        for (BigInteger t : taus) {
            if (t.signum() != 0) {
                throw new MacCheckAbort("Beaver-triple sacrifice FAILED: residual tau=" + t + " != 0 - a malformed triple (c != a*b) was delivered; aborting with no triple emitted");
            }
        }
        List<AuthTriple> out = new ArrayList<>();
        for (TripleWithPartners t : batch) out.add(t.keep());
        return out;
    }

    /**
     * A party's broadcast deviation in the online phase (models an active cheater). Null valueDelta / macDelta mean none;
     * macKey defaults to 0.
     */
    public record Deviation(int openIndex, int party, BigInteger valueDelta, BigInteger macDelta, Integer macKey) {}

    /** One partial opening as it reaches the MAC-check: the public value and macShares[key][party]. */
    public record OpenedValue(BigInteger value, BigInteger[][] macShares, String label) {}

    /** Arithmetic core of the batched MAC-check over an arbitrary modulus p; returns sigma[key][party]. */
    public static BigInteger[][] macResiduals(BigInteger p, BigInteger[][] alphaShares, List<OpenedValue> opened, BigInteger[][] challenges) {
        BigInteger[][] out = new BigInteger[alphaShares.length][];
        for (int l = 0; l < alphaShares.length; l++) {
            BigInteger[] r = challenges[l];
            BigInteger a = BigInteger.ZERO;
            for (int j = 0; j < opened.size(); j++) a = a.add(r[j].multiply(opened.get(j).value())).mod(p);
            BigInteger[] alphas = alphaShares[l];
            out[l] = new BigInteger[alphas.length];
            for (int i = 0; i < alphas.length; i++) {
                BigInteger gamma = BigInteger.ZERO;
                for (int j = 0; j < opened.size(); j++) gamma = gamma.add(r[j].multiply(opened.get(j).macShares()[l][i])).mod(p);
                out[l][i] = gamma.subtract(alphas[i].multiply(a)).mod(p);
            }
        }
        return out;
    }

    /** The SPDZ online engine: partial openings and the batched MAC-check. */
    public static final class SpdzEngine {
        private final MacContext ctx;
        private final List<Deviation> deviations;
        private final List<OpenedValue> opened = new ArrayList<>();
        private int counter = 0;

        public SpdzEngine(MacContext ctx, List<Deviation> deviations) {
            double bits = macSoundnessBits(1 + ctx.extraKeys().size());
            if (bits < MIN_MAC_SOUNDNESS_BITS) {
                throw new IllegalArgumentException("SpdzEngine: MAC context gives only " + Math.round(bits) + " bits of statistical soundness (< " + MIN_MAC_SOUNDNESS_BITS
                    + "); use setupMac(n, rng) with the default " + MAC_KEYS + " keys");
            }
            this.ctx = ctx;
            this.deviations = deviations == null ? List.of() : deviations;
        }

        public SpdzEngine(MacContext ctx) { this(ctx, List.of()); }

        public int openCount() { return counter; }

        public BigInteger open(AuthSV x, String label) {
            int idx = counter++;
            if (x.extraMac().length != ctx.extraKeys().size()) throw new IllegalArgumentException("open: value and MAC context disagree on the key count");
            BigInteger[] valueShares = x.value().clone();
            BigInteger[][] macShares = new BigInteger[1 + x.extraMac().length][];
            macShares[0] = x.mac().clone();
            for (int l = 0; l < x.extraMac().length; l++) macShares[l + 1] = x.extraMac()[l].clone();
            for (Deviation d : deviations) {
                if (d.openIndex() != idx) continue;
                if (d.party() < 0 || d.party() >= ctx.n()) throw new IllegalArgumentException("Deviation.party out of range");
                if (d.valueDelta() != null) valueShares[d.party()] = fadd(valueShares[d.party()], d.valueDelta());
                if (d.macDelta() != null) {
                    int key = d.macKey() == null ? 0 : d.macKey();
                    if (key < 0 || key >= macShares.length) throw new IllegalArgumentException("Deviation.macKey out of range");
                    macShares[key][d.party()] = fadd(macShares[key][d.party()], d.macDelta());
                }
            }
            BigInteger value = BigInteger.ZERO;
            for (BigInteger s : valueShares) value = fadd(value, s);
            opened.add(new OpenedValue(value, macShares, label));
            return value;
        }

        public BigInteger open(AuthSV x) { return open(x, ""); }

        /** Batched MAC-check over every partial open so far; throws {@link MacCheckAbort} on any inconsistency. */
        public void macCheck(FieldSource rng) {
            if (opened.isEmpty()) return;
            List<MacKey> keys = macKeys(ctx);
            BigInteger[][] challenges = new BigInteger[keys.size()][opened.size()];
            for (int l = 0; l < keys.size(); l++) for (int j = 0; j < opened.size(); j++) challenges[l][j] = rng.next();
            BigInteger[][] alphas = new BigInteger[keys.size()][];
            for (int l = 0; l < keys.size(); l++) alphas[l] = keys.get(l).alphaShares();
            BigInteger[][] sigma = macResiduals(PRIME, alphas, opened, challenges);

            for (int l = 0; l < sigma.length; l++) {
                BigInteger[] nonces = new BigInteger[sigma[l].length];
                for (int i = 0; i < nonces.length; i++) nonces[i] = rng.next();
                String[] commitments = new String[nonces.length];
                for (int i = 0; i < nonces.length; i++) commitments[i] = commit(sigma[l][i], nonces[i]);
                for (int i = 0; i < commitments.length; i++) {
                    if (!commit(sigma[l][i], nonces[i]).equals(commitments[i])) {
                        throw new MacCheckAbort("MAC-check: commitment from party " + i + " did not open consistently");
                    }
                }
            }
            for (int l = 0; l < sigma.length; l++) {
                BigInteger residual = BigInteger.ZERO;
                for (BigInteger s : sigma[l]) residual = fadd(residual, s);
                if (residual.signum() != 0) {
                    throw new MacCheckAbort("MAC-check FAILED (key " + l + "): residual " + residual + " != 0 — an actively-malicious party was detected; aborting with no output");
                }
            }
        }
    }

    /** Authenticated Beaver multiplication consuming {@code triple}; the d and e openings are recorded for the MAC-check. */
    public static AuthSV beaverMulAuth(AuthSV x, AuthSV y, AuthTriple triple, MacContext ctx, SpdzEngine engine, String label) {
        requireSame(x, triple.a());
        requireSame(x, triple.b());
        requireSame(x, triple.c());
        requireSame(x, y);
        BigInteger d = engine.open(subAuth(x, triple.a()), label + ":d");
        BigInteger e = engine.open(subAuth(y, triple.b()), label + ":e");
        AuthSV z = addAuth(triple.c(), addAuth(scaleAuth(triple.b(), d), scaleAuth(triple.a(), e)));
        return addPublicAuth(z, fmul(d, e), ctx);
    }

    public static BigInteger authValue(AuthSV x) {
        BigInteger a = BigInteger.ZERO;
        for (BigInteger s : x.value()) a = fadd(a, s);
        return a;
    }

    /** SHA-256 binding commitment to a field element under a nonce. */
    static String commit(BigInteger value, BigInteger nonce) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(Json.utf8((value.toString(16) + ":" + nonce.toString(16))));
            return HexFormat.of().formatHex(h);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void requireSame(AuthSV x, AuthSV y) {
        if (x.value().length != y.value().length || x.mac().length != y.mac().length) {
            throw new IllegalArgumentException("authenticated shared values must have the same party count");
        }
        if (x.extraMac().length != y.extraMac().length) throw new IllegalArgumentException("authenticated shared values must carry the same number of MAC keys");
        for (int l = 0; l < x.extraMac().length; l++) {
            if (x.extraMac()[l].length != y.extraMac()[l].length) throw new IllegalArgumentException("authenticated shared values must have the same party count");
        }
    }
}
