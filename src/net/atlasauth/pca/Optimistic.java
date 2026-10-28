package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Optimistic-path verification (extension layer): bonded claims, the challenge window, fraud proofs (wire level) and
 * guardian-signed settlement records. Inputs are parsed JSON values; nothing here throws on hostile input.
 *
 * <p>A fraud proof is only convincing because the settlement layer RE-RUNS the Policy VM on its server-held open-time
 * snapshot; {@link #fraudProofWireCheck} does not do that (no native SDK evaluates the Policy VM decision). It checks that
 * the proof is well formed, names this claim and bond, and carries the decision its kind requires.
 */
public final class Optimistic {
    private Optimistic() {}

    public static final String CLAIM_DOMAIN = "atlas-pca/optimistic/v1\0";
    public static final String SETTLEMENT_DOMAIN = "atlas-pca/bond-settlement/v1\0";
    static final String IRREVERSIBLE = "irreversible";
    static final double DEFAULT_R_MARGIN = 1e-9;

    /** Bounds a claim's issued_at skew and window length (milliseconds). */
    public static final class ChallengeWindowPolicy {
        public final double minWindowMs, maxWindowMs, maxSkewMs;
        public ChallengeWindowPolicy(double minWindowMs, double maxWindowMs, double maxSkewMs) {
            this.minWindowMs = minWindowMs;
            this.maxWindowMs = maxWindowMs;
            this.maxSkewMs = maxSkewMs;
        }
    }

    /** The library default (1 s minimum, 24 h maximum, 5 s skew). */
    public static final ChallengeWindowPolicy DEFAULT_POLICY = new ChallengeWindowPolicy(1000, 86_400_000, 5000);

    private static Double finite(Object v) {
        Double d = IntentJs.num(v);
        return d != null && !d.isNaN() && !d.isInfinite() ? d : null;
    }

    private static Double nonNeg(Object v) {
        Double d = finite(v);
        return d != null && d >= 0 ? d : null;
    }

    /** A JSON object (and, like JavaScript, an array) is an object; anything else is not. */
    private static Map<String, Object> object(Object v) {
        if (v instanceof Map) return Ledger.map(v);
        if (v instanceof List) return new LinkedHashMap<>();
        return null;
    }

    /** 0 = the body cannot be canonicalized, 1 = bad signature, 2 = signature good. */
    private static int signedLenient(String pub, String domain, Map<String, Object> body, Object sig) {
        byte[] c;
        try {
            c = Json.canonicalize(body).getBytes(StandardCharsets.UTF_8);
        } catch (RuntimeException e) {
            return 0;
        }
        if (pub == null || !(sig instanceof String)) return 1;
        return Pca.verifyB64u(pub, Pca.concat(domain.getBytes(StandardCharsets.UTF_8), c), (String) sig) ? 2 : 1;
    }

    private static Map<String, Object> without(Map<String, Object> m, String... drop) {
        Map<String, Object> out = new LinkedHashMap<>(m);
        for (String k : drop) out.remove(k);
        return out;
    }

    /**
     * The FIRST check a bonded claim fails, or "ok": malformed, irreversible, digest, claimed_r, window, signature. The claim
     * must cover expectedPcactnDigest, be signed by signerPublic, and its window must sit within the policy of serverNow.
     */
    public static String claimCheck(Object claim, String expectedPcactnDigest, String signerPublic, double serverNow, ChallengeWindowPolicy p) {
        Map<String, Object> c = object(claim);
        if (c == null) return "malformed";
        if (IRREVERSIBLE.equals(c.get("reversibility_class"))) return "irreversible";
        Object d = c.get("pcactn_digest");
        if (!(d instanceof String) || !d.equals(expectedPcactnDigest)) return "digest";
        if (finite(c.get("claimed_r")) == null) return "claimed_r";
        Double issued = finite(c.get("issued_at")), window = finite(c.get("challenge_window_ms"));
        if (issued == null || window == null || Double.isNaN(serverNow) || Double.isInfinite(serverNow)
                || Math.abs(issued - serverNow) > p.maxSkewMs || window < p.minWindowMs || window > p.maxWindowMs) return "window";
        int s = signedLenient(signerPublic, CLAIM_DOMAIN, without(c, "sig"), c.get("sig"));
        if (s == 0) return "malformed";
        return s == 2 ? "ok" : "signature";
    }

    /** The last instant (epoch ms) at which a challenge is accepted: issued_at + window. */
    public static double challengeWindowEnd(double issuedAt, double windowMs) { return issuedAt + windowMs; }

    /** True while challenges are accepted: now &lt;= issued_at + window (inclusive end). */
    public static boolean withinChallengeWindow(double issuedAt, double windowMs, double now) {
        return !Double.isNaN(now) && !Double.isInfinite(now) && now <= challengeWindowEnd(issuedAt, windowMs);
    }

    /** "open" while challenges are accepted, else "finalized". */
    public static String claimStatus(double issuedAt, double windowMs, double now) {
        return withinChallengeWindow(issuedAt, windowMs, now) ? "open" : "finalized";
    }

    /** JavaScript === between two JSON members (numbers by value, otherwise by canonical form; both absent are equal). */
    private static boolean memberEq(Map<String, Object> m1, Map<String, Object> m2, String k) {
        boolean h1 = m1.containsKey(k), h2 = m2.containsKey(k);
        if (h1 != h2) return false;
        if (!h1) return true;
        Object a = m1.get(k), b = m2.get(k);
        Double x = IntentJs.num(a);
        if (x != null) {
            Double y = IntentJs.num(b);
            return y != null && x.doubleValue() == y.doubleValue();
        }
        return Ledger.same(a, b);
    }

    /**
     * The first wire-level check a fraud proof fails against the claim it names, or "ok": malformed, digest, bond, claimed_r,
     * kind, consistency. See the class comment for what it does not do.
     */
    public static String fraudProofWireCheck(Object claimO, Object proofO) {
        Map<String, Object> c = Ledger.map(claimO), p = Ledger.map(proofO);
        if (c == null || p == null) return "malformed";
        Map<String, Object> d = Ledger.map(p.get("decision"));
        if (d == null) return "malformed";
        Object rel0 = d.get("releaseGuardianShare"), opt0 = d.get("optimisticAllowed");
        Double r = finite(d.get("r"));
        if (!(rel0 instanceof Boolean) || !(opt0 instanceof Boolean) || r == null
                || !(p.get("pcactn_digest") instanceof String) || !(p.get("bond_ref") instanceof String) || !(p.get("reason") instanceof String)) return "malformed";
        boolean rel = (Boolean) rel0, opt = (Boolean) opt0;
        if (!memberEq(p, c, "pcactn_digest")) return "digest";
        if (!memberEq(p, c, "bond_ref")) return "bond";
        if (!memberEq(p, c, "claimed_r")) return "claimed_r";
        Object kind = p.get("kind");
        double margin = DEFAULT_R_MARGIN;
        Double m = finite(p.get("r_margin"));
        if (m != null) margin = Math.max(0, m);
        boolean holds;
        if ("irreversible".equals(kind)) {
            Object ev = null; // proof.evidence?.action?.action?.reversibility_class
            Map<String, Object> e = Ledger.map(p.get("evidence"));
            Map<String, Object> a = e == null ? null : Ledger.map(e.get("action"));
            Map<String, Object> a2 = a == null ? null : Ledger.map(a.get("action"));
            if (a2 != null) ev = a2.get("reversibility_class");
            holds = IRREVERSIBLE.equals(c.get("reversibility_class")) || IRREVERSIBLE.equals(ev);
        } else if ("policy-denied".equals(kind)) {
            holds = !rel;
        } else if ("optimistic-not-allowed".equals(kind)) {
            holds = rel && !opt;
        } else if ("risk-understated".equals(kind)) {
            Double cr = finite(c.get("claimed_r"));
            holds = cr != null && rel && opt && r > cr + margin;
        } else {
            return "kind";
        }
        return holds ? "ok" : "consistency";
    }

    private static boolean nonEmpty(Object v) { return v instanceof String && !((String) v).isEmpty(); }

    /**
     * The first check a settlement record fails, or "ok": malformed, suite, shape, split, signature. The guardian signature is
     * checked last, over the lenient canonical body without sig / pq_sig.
     */
    public static String settlementWireCheck(Object recordO, String guardianPublic) { return settlementWireCheck(recordO, guardianPublic, null); }

    /** A PQ half verifies only under {@code pins[guardianPublic]}; an alg this build cannot verify (unknown or unimplemented) answers {@code suite}. */
    public static String settlementWireCheck(Object recordO, String guardianPublic, Map<String, Object> pins) {
        Map<String, Object> r = Ledger.map(recordO);
        if (r == null) return "malformed";
        if (Pq.resolveSigAlg(r.get("alg"), r.containsKey("alg")) == null) return "suite";
        Object action = r.get("action");
        boolean slash = "slash".equals(action);
        Double amount = finite(r.get("amount"));
        boolean hasSplit = r.containsKey("split");
        Object ev = r.get("evidenceDigest");
        boolean evOK = ev instanceof String;
        boolean epochOK = true;
        if (r.containsKey("guardian_epoch")) {
            Object e = r.get("guardian_epoch");
            epochOK = IntentJs.num(e) != null && IntentJs.isSafeInteger(e) && IntentJs.num(e) >= 0;
        }
        boolean shape = nonEmpty(r.get("claimId"))
                && ("open".equals(action) || "release".equals(action) || slash)
                && amount != null && amount > 0
                && nonEmpty(r.get("from")) && nonEmpty(r.get("to"))
                && finite(r.get("at")) != null
                && evOK && ((String) ev).isEmpty() != slash
                && (slash ? Ledger.map(r.get("split")) != null : !hasSplit)
                && r.get("sig") instanceof String
                && epochOK;
        if (!shape) return "shape";
        if (slash) {
            Map<String, Object> sp = Ledger.map(r.get("split"));
            Double sa = IntentJs.num(sp.get("amount"));
            Double cr = nonNeg(sp.get("challengerReward")), vc = nonNeg(sp.get("victimCompensation")), tr = nonNeg(sp.get("treasuryRemainder"));
            Object ta = sp.get("treasuryAccount");
            boolean conserved = sa != null && sa.doubleValue() == amount.doubleValue()
                    && cr != null && vc != null && tr != null && (cr + vc) + tr == amount.doubleValue()
                    && nonEmpty(sp.get("victimAccount"))
                    && ta instanceof String && ta.equals(r.get("to"));
            if (conserved) {
                if (sp.containsKey("challengerAccount") && sp.get("challengerAccount") == null) {
                    conserved = cr == 0 && vc == 0 && tr == amount.doubleValue(); // anonymous challenge: everything to the treasury
                } else {
                    conserved = nonEmpty(sp.get("challengerAccount"));
                }
            }
            if (!conserved) return "split";
        }
        byte[] c;
        try {
            c = Json.canonicalize(without(r, "sig", "pq_sig")).getBytes(StandardCharsets.UTF_8);
        } catch (RuntimeException e) {
            return "malformed";
        }
        byte[] msg = Pca.concat(SETTLEMENT_DOMAIN.getBytes(StandardCharsets.UTF_8), c);
        return guardianPublic != null && IntentJs.verifyPinnedSuite(r.get("alg"), r.containsKey("alg"), guardianPublic, r.get("pq_pk"), msg, r.get("sig"), r.get("pq_sig"), pins) ? "ok" : "signature";
    }
}
