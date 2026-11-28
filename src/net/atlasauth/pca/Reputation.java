package net.atlasauth.pca;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reputation and underwriting: an explainable score in [0,1] from a subject's activity and disputes, a transparent premium curve, signed
 * coverage quotes the verifier recomputes, and a finite fail-closed {@link Pool} of insurance capital. Inputs and results are JSON objects.
 */
public final class Reputation {
    private Reputation() {}

    public static final int MAX_REPUTATION_RECORDS = 100_000;
    public static final String COVERAGE_QUOTE_DOMAIN = "atlas-pca/coverage-quote/v1\0";
    private static final Set<String> OUTCOMES = Set.of("auto", "step_up", "deny", "executed");

    private static String fixed(double x, int digits) { return new BigDecimal(x).setScale(digits, RoundingMode.HALF_UP).toPlainString(); } // JavaScript toFixed

    private static String js(double x) { return AttestCommon.jsNumString(x); }

    private static boolean fin(Object o) { return StoreJs.isFinite(o); }

    private static double d(Object o) { return StoreJs.dbl(o); }

    /** The member as the reference reads it with a default of []: absent is empty, a non-array (even null) is invalid (null result). */
    private static List<?> listOr(Map<String, Object> m, String k) { return !m.containsKey(k) ? new ArrayList<Object>() : m.get(k) instanceof List ? (List<?>) m.get(k) : null; }

    /** Why the input is unusable, or null. */
    public static String validateReputationInput(Map<String, Object> input) {
        Object subject = input == null ? null : input.get("subject");
        if (!(subject instanceof String) || ((String) subject).isEmpty()) return "subject must be a non-empty string";
        List<?> events = listOr(input, "events"), disputes = listOr(input, "disputes");
        if (events == null || disputes == null) return "events and disputes must be arrays";
        if (events.size() > MAX_REPUTATION_RECORDS || disputes.size() > MAX_REPUTATION_RECORDS) return "too many records";
        for (Object e : events) {
            Map<String, Object> m = StoreJs.map(e);
            if (m == null || !(m.get("outcome") instanceof String) || !OUTCOMES.contains(m.get("outcome"))) return "event with an unknown outcome";
        }
        for (Object o : disputes) {
            Map<String, Object> dd = StoreJs.map(o);
            if (dd == null || !(dd.get("id") instanceof String) || ((String) dd.get("id")).isEmpty()) return "dispute without an id";
            if (!subject.equals(dd.get("subject"))) return "dispute for another subject";
            if (!(dd.get("slashed") instanceof Boolean)) return "dispute.slashed must be a boolean";
            if (!fin(dd.get("at")) || d(dd.get("at")) < 0) return "dispute.at must be finite and >= 0";
            if (dd.containsKey("amount") && (!fin(dd.get("amount")) || d(dd.get("amount")) < 0)) return "dispute.amount must be finite and >= 0";
        }
        return null;
    }

    private static Map<String, Object> rep(Object subject, int actions, int autos, int stepUps, int denies, int slashes, int disputes, double score, List<Object> factors) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("subject", subject);
        m.put("actions", StoreJs.num((long) actions));
        m.put("autos", StoreJs.num((long) autos));
        m.put("stepUps", StoreJs.num((long) stepUps));
        m.put("denies", StoreJs.num((long) denies));
        m.put("slashes", StoreJs.num((long) slashes));
        m.put("disputes", StoreJs.num((long) disputes));
        m.put("score", StoreJs.num(score));
        m.put("factors", factors);
        return m;
    }

    private static List<Object> one(String s) { List<Object> l = new ArrayList<>(); l.add(s); return l; }

    /**
     * The reputation of a subject: starts at 1 and subtracts explainable penalties (the deny rate, a milder step-up rate and, dominant, slashed
     * disputes); a subject with no history scores a neutral 0.5; unusable input fails closed to 0.
     */
    public static Map<String, Object> reputation(Map<String, Object> input) {
        String bad = validateReputationInput(input);
        if (bad != null) {
            Object s = input == null ? null : input.get("subject");
            return rep(s == null ? "" : s instanceof String ? s : IntentRevocation.jsText(s, true), 0, 0, 0, 0, 0, 0, 0, one("invalid input: " + bad));
        }
        List<?> events = listOr(input, "events");
        Set<String> seen = new HashSet<>();
        List<Map<String, Object>> disputes = new ArrayList<>();
        for (Object o : listOr(input, "disputes")) {
            Map<String, Object> dd = StoreJs.map(o);
            if (seen.add((String) dd.get("id"))) disputes.add(dd);
        }
        int actions = events.size(), autos = 0, stepUps = 0, denies = 0, slashes = 0;
        for (Object e : events) {
            Object out = StoreJs.map(e).get("outcome");
            if ("auto".equals(out)) autos++;
            else if ("step_up".equals(out)) stepUps++;
            else if ("deny".equals(out)) denies++;
        }
        for (Map<String, Object> dd : disputes) if (Boolean.TRUE.equals(dd.get("slashed"))) slashes++;
        if (actions == 0 && disputes.isEmpty()) return rep(input.get("subject"), actions, autos, stepUps, denies, slashes, 0, 0.5, one("unproven (no history)"));

        List<Object> factors = new ArrayList<>();
        double score = 1;
        if (actions > 0) {
            double denyRate = (double) denies / actions, stepUpRate = (double) stepUps / actions;
            if (denyRate > 0) {
                score -= 0.6 * denyRate;
                factors.add("deny rate " + fixed(denyRate * 100, 0) + "%");
            }
            if (stepUpRate > 0) {
                score -= 0.15 * stepUpRate;
                factors.add("step-up rate " + fixed(stepUpRate * 100, 0) + "%");
            }
        }
        if (slashes > 0) {
            score -= Math.min(0.8, 0.3 * slashes);
            factors.add(slashes + " slashed dispute" + (slashes > 1 ? "s" : ""));
        }
        if (factors.isEmpty()) factors.add("clean history");
        return rep(input.get("subject"), actions, autos, stepUps, denies, slashes, disputes.size(), Math.max(0, Math.min(1, score)), factors);
    }

    // ---- underwriting ----

    private static double opt(Map<String, Object> opts, String k, double dflt) {
        Object v = opts == null ? null : opts.get(k);
        return v == null ? dflt : StoreJs.dbl(v) == null ? Double.NaN : StoreJs.dbl(v);
    }

    private static Map<String, Object> pricing(boolean declined, double premium, double coverage, String rationale) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("declined", declined);
        m.put("premium", StoreJs.num(premium));
        m.put("coverage", StoreJs.num(coverage));
        m.put("rationale", rationale);
        return m;
    }

    /**
     * Price coverage of {@code exposure} for a subject with {@code score} (null: invalid): {@code premium = baseRate * exposure * (1 + riskLoad * (1 - score))},
     * declined below {@code minScore}. {@code opts} may carry {@code baseRate} (0.01), {@code riskLoad} (4) and {@code minScore} (0.25). A non-finite exposure counts as 0.
     */
    public static Map<String, Object> priceCoverage(Double score, double exposure, Map<String, Object> opts) {
        double baseRate = opt(opts, "baseRate", 0.01), riskLoad = opt(opts, "riskLoad", 4), minScore = opt(opts, "minScore", 0.25);
        if (score == null || Double.isNaN(score) || Double.isInfinite(score) || score < 0 || score > 1) return pricing(true, 0, 0, "invalid reputation score");
        double exp = !Double.isNaN(exposure) && !Double.isInfinite(exposure) ? Math.max(0, exposure) : 0;
        if (!(score >= minScore)) return pricing(true, 0, 0, "reputation " + fixed(score, 2) + " below underwriting floor " + js(minScore));
        double load = 1 + riskLoad * (1 - score);
        return pricing(false, baseRate * exp * load, exp, "base " + js(baseRate) + " × exposure " + js(exp) + " × load " + fixed(load, 2) + " (score " + fixed(score, 2) + ")");
    }

    // ---- signed coverage quotes ----

    private static byte[] quoteMessage(Map<String, Object> claim) {
        return Pca.concat(COVERAGE_QUOTE_DOMAIN.getBytes(StandardCharsets.UTF_8), Json.canonicalize(claim).getBytes(StandardCharsets.UTF_8));
    }

    /** Price and sign a quote for {@code rep} (a reputation). Throws on a bad score, expiry or exposure (never signs a nonsense quote). */
    public static Map<String, Object> issueCoverageQuote(Map<String, Object> rep, double exposure, Keys.EdKey underwriter, double now, double ttlMs, Map<String, Object> opts) {
        if (Double.isNaN(exposure) || Double.isInfinite(exposure) || exposure < 0) throw new IllegalStateException("issueCoverageQuote: exposure must be finite and >= 0");
        if (Double.isNaN(now) || Double.isInfinite(now) || !(ttlMs > 0) || Double.isInfinite(ttlMs)) throw new IllegalStateException("issueCoverageQuote: now and ttlMs must be finite, ttlMs > 0");
        Double score = StoreJs.dbl(rep.get("score"));
        if (score == null || Double.isNaN(score) || Double.isInfinite(score) || score < 0 || score > 1) throw new IllegalStateException("issueCoverageQuote: invalid reputation score");
        double baseRate = opt(opts, "baseRate", 0.01), riskLoad = opt(opts, "riskLoad", 4), minScore = opt(opts, "minScore", 0.25);
        Map<String, Object> po = new LinkedHashMap<>();
        po.put("baseRate", StoreJs.num(baseRate));
        po.put("riskLoad", StoreJs.num(riskLoad));
        po.put("minScore", StoreJs.num(minScore));
        Map<String, Object> p = priceCoverage(score, exposure, po);
        if (!rep.containsKey("subject")) throw new IllegalArgumentException("canonicalize: unsupported type undefined"); // the reference signs the claim: an absent member is not canonical
        Map<String, Object> claim = new LinkedHashMap<>();
        claim.put("v", StoreJs.num(1L));
        claim.put("subject", rep.get("subject"));
        claim.put("score", rep.get("score"));
        claim.put("exposure", StoreJs.num(exposure));
        claim.put("baseRate", StoreJs.num(baseRate));
        claim.put("riskLoad", StoreJs.num(riskLoad));
        claim.put("minScore", StoreJs.num(minScore));
        claim.put("declined", p.get("declined"));
        claim.put("premium", p.get("premium"));
        claim.put("coverage", p.get("coverage"));
        claim.put("issued_at", StoreJs.num(now));
        claim.put("expires_at", StoreJs.num(now + ttlMs));
        claim.put("underwriter", underwriter.id());
        Map<String, Object> q = new LinkedHashMap<>(claim);
        q.put("sig", Keys.b64u(underwriter.sign(quoteMessage(claim))));
        return q;
    }

    private static Map<String, Object> verdict(String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", reason == null);
        if (reason != null) m.put("reason", reason);
        return m;
    }

    /** Verify a quote: pinned underwriter, signature, validity window, and the premium RECOMPUTED from the stated inputs. {@code {ok}} or {@code {ok:false, reason}}. Never throws. */
    public static Map<String, Object> verifyCoverageQuote(Object quote, String underwriter, double now) {
        try {
            Map<String, Object> q = StoreJs.map(quote);
            if (q == null || !(q.get("v") instanceof Json.Num) || d(q.get("v")) != 1 || !(q.get("sig") instanceof String)) return verdict("malformed");
            for (String k : new String[] {"score", "exposure", "baseRate", "riskLoad", "minScore", "premium", "coverage", "issued_at", "expires_at"}) if (!fin(q.get(k))) return verdict("malformed");
            if (!(q.get("declined") instanceof Boolean) || !(q.get("subject") instanceof String)) return verdict("malformed");
            if (underwriter == null || !underwriter.equals(q.get("underwriter"))) return verdict("underwriter");
            Map<String, Object> claim = new LinkedHashMap<>(q);
            claim.remove("sig");
            if (!Pca.verifyB64u((String) q.get("underwriter"), quoteMessage(claim), (String) q.get("sig"))) return verdict("signature");
            if (Double.isNaN(now) || Double.isInfinite(now) || now < d(q.get("issued_at"))) return verdict("not-yet-valid");
            if (now >= d(q.get("expires_at"))) return verdict("expired");
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("baseRate", q.get("baseRate"));
            o.put("riskLoad", q.get("riskLoad"));
            o.put("minScore", q.get("minScore"));
            Map<String, Object> p = priceCoverage(d(q.get("score")), d(q.get("exposure")), o);
            if (!p.get("declined").equals(q.get("declined")) || d(p.get("premium")) != d(q.get("premium")) || d(p.get("coverage")) != d(q.get("coverage"))) return verdict("price-mismatch");
            return verdict(null);
        } catch (RuntimeException e) {
            return verdict("malformed");
        }
    }

    // ---- the capital pool ----

    /**
     * A finite, fail-closed insurance capital pool. Premiums (priced via {@link #priceCoverage}) are credited; victim payouts are debited and REFUSED
     * when they exceed the free capital (scarce collateral). {@code initial + premiumsIn - payoutsOut == balance} always.
     */
    public static final class Pool {
        private final double initial;
        private double premiumsIn = 0, payoutsOut = 0;

        public Pool(double initial) {
            if (Double.isNaN(initial) || Double.isInfinite(initial) || initial < 0) throw new IllegalStateException("InsuranceCapitalPool: initial capital must be a non-negative finite number");
            this.initial = initial;
        }

        public synchronized double balance() { return initial + premiumsIn - payoutsOut; }

        /** {@code {initial, premiumsIn, payoutsOut, balance}}. */
        public synchronized Map<String, Object> state() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("initial", StoreJs.num(initial));
            m.put("premiumsIn", StoreJs.num(premiumsIn));
            m.put("payoutsOut", StoreJs.num(payoutsOut));
            m.put("balance", StoreJs.num(balance()));
            return m;
        }

        /** Price coverage without touching the pool. */
        public Map<String, Object> quote(Double score, double exposure, Map<String, Object> opts) { return priceCoverage(score, exposure, opts); }

        /** Price coverage and, if not declined, credit the premium; returns {@code {pricing, state}}. */
        public synchronized Map<String, Object> collectPremium(Double score, double exposure, Map<String, Object> opts) {
            Map<String, Object> pr = priceCoverage(score, exposure, opts);
            double premium = d(pr.get("premium"));
            if (!Boolean.TRUE.equals(pr.get("declined")) && premium > 0) {
                if (Double.isNaN(premium) || Double.isInfinite(premium) || premium < 0) throw new IllegalStateException("collectPremium: priced premium is not a non-negative finite number");
                premiumsIn += premium;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("pricing", pr);
            m.put("state", state());
            return m;
        }

        public synchronized boolean canCover(double amount) { return !Double.isNaN(amount) && !Double.isInfinite(amount) && amount >= 0 && balance() >= amount; }

        /** Pay {@code amount} of victim compensation; REFUSED (throws) when non-positive, non-finite or above the free capital. */
        public synchronized Map<String, Object> payClaim(double amount) {
            if (Double.isNaN(amount) || Double.isInfinite(amount) || amount <= 0) throw new IllegalStateException("payClaim: amount must be a positive finite number");
            if (!(Double.isFinite(balance()) && amount <= balance())) throw new IllegalStateException("payClaim: insufficient pool capital (need " + js(amount) + ", have " + js(balance()) + ")");
            payoutsOut += amount;
            return state();
        }
    }
}
