package net.atlasauth.pca.grants;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;

/**
 * Shadow policy rollout. An enforced bundle revision may list candidate bundles in {@code shadow}; {@link #runShadow} computes the
 * enforced decision first and returns it untouched, recording what each candidate would have said. Every divergence becomes a
 * verifier-signed diff; {@link #promotionGate} must pass before {@link #promoteShadow} builds the next revision's body. Nothing here
 * decides an action: it is analysis and rollout tooling that runs beside the verifier.
 */
public final class Shadow {
    private Shadow() {}

    public static final String SHADOW_DIFF_DOMAIN = "atlas-pca/shadow-diff/v1\0";
    public static final String WIDENING_EXPLANATION_DOMAIN = "atlas-pca/shadow-widening-explanation/v1\0";
    public static final String PROMOTION_APPROVAL_DOMAIN = "atlas-pca/shadow-promotion-approval/v1\0";

    private static int rank(Object k) { return "deny".equals(k) ? 0 : "escalate".equals(k) ? 1 : "allow".equals(k) ? 2 : -1; }

    private static boolean isKind(Object k) { return rank(k) >= 0; }

    /** A candidate bundle: its digest and its pure decision function. */
    public static final class Candidate {
        public final String digest;
        public final Function<Object, String> decide;
        public Candidate(String digest, Function<Object, String> decide) { this.digest = digest; this.decide = decide; }
    }

    /** What one candidate said. {@code decision} is a decision kind or {@code error}. */
    public static final class Outcome {
        public final String digest;
        public final String decision;
        public final boolean diverged;
        /** The candidate would have been MORE permissive than the enforced decision. */
        public final boolean widening;
        Outcome(String digest, String decision, boolean diverged, boolean widening) { this.digest = digest; this.decision = decision; this.diverged = diverged; this.widening = widening; }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("digest", digest);
            m.put("decision", decision);
            m.put("diverged", diverged);
            m.put("widening", widening);
            return m;
        }
    }

    /** The enforced decision and what each candidate would have said. */
    public static final class Run {
        public final String decision;
        public final List<Outcome> shadow;
        Run(String decision, List<Outcome> shadow) { this.decision = decision; this.shadow = shadow; }
    }

    public static Run runShadow(Object input, Function<Object, String> enforced, List<Candidate> candidates) {
        String decision = enforced.apply(input);
        List<Outcome> out = new ArrayList<>();
        for (Candidate c : candidates) {
            try {
                String d = c.decide.apply(deepCopy(input)); // the candidate gets a copy: it cannot mutate the enforced input
                if (!isKind(d)) out.add(new Outcome(c.digest, "error", false, false));
                else out.add(new Outcome(c.digest, d, !d.equals(decision), rank(d) > rank(decision)));
            } catch (RuntimeException e) {
                out.add(new Outcome(c.digest, "error", false, false));
            }
        }
        return new Run(decision, out);
    }

    @SuppressWarnings("unchecked")
    private static Object deepCopy(Object v) {
        if (v instanceof Map) {
            Map<String, Object> o = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) o.put(e.getKey(), deepCopy(e.getValue()));
            return o;
        }
        if (v instanceof List) {
            List<Object> o = new ArrayList<>();
            for (Object x : (List<Object>) v) o.add(deepCopy(x));
            return o;
        }
        return v;
    }

    /** The {@code shadow} member of a decision record, from the outcomes. */
    public static List<Object> shadowRecordField(List<Outcome> o) {
        List<Object> out = new ArrayList<>();
        for (Outcome x : o) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("digest", x.digest);
            m.put("decision", x.decision);
            m.put("diverged", x.diverged);
            out.add(m);
        }
        return out;
    }

    private static Map<String, Object> pick(Map<String, Object> o, String... keys) {
        Map<String, Object> b = new LinkedHashMap<>();
        for (String k : keys) b.put(k, o.get(k));
        return b;
    }

    private static Map<String, Object> without(Map<String, Object> m, String k) {
        Map<String, Object> o = new LinkedHashMap<>(m);
        o.remove(k);
        return o;
    }

    private static Map<String, Object> diffBody(Map<String, Object> d) {
        return pick(d, "v", "shadow_digest", "enforced_digest", "action_digest", "enforced", "shadow", "widening", "at", "signer");
    }

    private static boolean isOne(Object v) { return Json.isSafeInt(v) && Json.asLong(v) == 1; }

    /** A well formed shadow diff signed by its signer ({@code signer} null = any signer). Never throws. */
    public static boolean verifyShadowDiff(Object dObj, String signer) {
        try {
            Map<String, Object> d = Sig.map(dObj);
            if (d == null || !isOne(d.get("v")) || !Sig.isStr(d.get("shadow_digest"), 128) || !Sig.isStr(d.get("enforced_digest"), 128)
                || !Sig.isStr(d.get("action_digest"), 128) || !isKind(d.get("enforced")) || !isKind(d.get("shadow")) || !(d.get("widening") instanceof Boolean)
                || !Sig.isSafeInt(d.get("at")) || !Sig.isStr(d.get("signer"), 128)) return false;
            if (d.get("enforced").equals(d.get("shadow")) || ((Boolean) d.get("widening")) != (rank(d.get("shadow")) > rank(d.get("enforced")))) return false;
            if (signer != null && !signer.equals(d.get("signer"))) return false;
            Map<String, Object> rest = without(d, "sig");
            return Sig.verifyBody(SHADOW_DIFF_DOMAIN, diffBody(rest), (String) rest.get("signer"), d.get("sig"));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Per-candidate counters. */
    public static final class Stats {
        public long total, diverged, widened, tightened, errors;

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("total", total);
            m.put("diverged", diverged);
            m.put("widened", widened);
            m.put("tightened", tightened);
            m.put("errors", errors);
            return m;
        }
    }

    /** Collects the signed diffs and counters per candidate. In memory: persist {@code diffs()} to the decision log for the audit trail. */
    public static final class ShadowLog {
        private final Map<String, Stats> stat = new HashMap<>();
        private final Map<String, List<Map<String, Object>>> list = new HashMap<>();
        private final Keys.EdKey secret;

        public ShadowLog(Keys.EdKey secret) { this.secret = secret; }

        public String signer() { return Sig.signerOf(secret); }

        /** Count one observation; sign and keep a diff when the candidate diverged. Returns the diff or null. */
        public synchronized Map<String, Object> observe(String enforcedDigest, String actionDigest, String enforced, Outcome outcome, long at) {
            Stats s = stat.computeIfAbsent(outcome.digest, k -> new Stats());
            s.total++;
            if ("error".equals(outcome.decision)) { s.errors++; return null; }
            if (!outcome.diverged) return null;
            s.diverged++;
            if (outcome.widening) s.widened++; else s.tightened++;
            Map<String, Object> base = new LinkedHashMap<>();
            base.put("v", 1L);
            base.put("shadow_digest", outcome.digest);
            base.put("enforced_digest", enforcedDigest);
            base.put("action_digest", actionDigest);
            base.put("enforced", enforced);
            base.put("shadow", outcome.decision);
            base.put("widening", outcome.widening);
            base.put("at", at);
            base.put("signer", signer());
            Map<String, Object> diff = new LinkedHashMap<>(base);
            diff.put("sig", Sig.signBody(SHADOW_DIFF_DOMAIN, diffBody(base), secret));
            list.computeIfAbsent(outcome.digest, k -> new ArrayList<>()).add(diff);
            return diff;
        }

        public synchronized Stats stats(String digest) {
            Stats s = stat.get(digest);
            Stats c = new Stats();
            if (s != null) { c.total = s.total; c.diverged = s.diverged; c.widened = s.widened; c.tightened = s.tightened; c.errors = s.errors; }
            return c;
        }

        public synchronized List<Map<String, Object>> diffs(String digest) {
            List<Map<String, Object>> l = list.get(digest);
            return l == null ? new ArrayList<Map<String, Object>>() : new ArrayList<>(l);
        }
    }

    private static Map<String, Object> expBody(Map<String, Object> e) { return pick(e, "v", "shadow_digest", "action_digest", "reason_digest", "principal"); }

    /** A principal states that this widening is intended; {@code e} = {shadow_digest, action_digest, reason_digest}. */
    public static Map<String, Object> signWideningExplanation(Keys.EdKey secret, Map<String, Object> e) {
        Map<String, Object> base = new LinkedHashMap<>();
        base.put("v", 1L);
        base.putAll(e);
        base.put("principal", Sig.signerOf(secret));
        base.put("sig", Sig.signBody(WIDENING_EXPLANATION_DOMAIN, expBody(base), secret));
        return base;
    }

    private static boolean verifyExplanation(Object eo) {
        Map<String, Object> e = Sig.map(eo);
        if (e == null || !isOne(e.get("v")) || !Sig.isStr(e.get("shadow_digest"), 128) || !Sig.isStr(e.get("action_digest"), 128)
            || !Sig.isStr(e.get("reason_digest"), 128) || !Sig.isStr(e.get("principal"), 128)) return false;
        return Sig.verifyBody(WIDENING_EXPLANATION_DOMAIN, expBody(e), (String) e.get("principal"), e.get("sig"));
    }

    private static Map<String, Object> apBody(Map<String, Object> a) { return pick(a, "v", "shadow_digest", "enforced_digest", "at", "principal"); }

    /** {@code a} = {shadow_digest, enforced_digest, at}. */
    public static Map<String, Object> signPromotionApproval(Keys.EdKey secret, Map<String, Object> a) {
        Map<String, Object> base = new LinkedHashMap<>();
        base.put("v", 1L);
        base.putAll(a);
        base.put("principal", Sig.signerOf(secret));
        base.put("sig", Sig.signBody(PROMOTION_APPROVAL_DOMAIN, apBody(base), secret));
        return base;
    }

    private static boolean verifyApproval(Object ao) {
        Map<String, Object> a = Sig.map(ao);
        if (a == null || !isOne(a.get("v")) || !Sig.isStr(a.get("shadow_digest"), 128) || !Sig.isStr(a.get("enforced_digest"), 128)
            || !Sig.isSafeInt(a.get("at")) || !Sig.isStr(a.get("principal"), 128)) return false;
        return Sig.verifyBody(PROMOTION_APPROVAL_DOMAIN, apBody(a), (String) a.get("principal"), a.get("sig"));
    }

    private static Map<String, Object> no(String code, String reason, List<String> unexplained) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("ok", false);
        r.put("code", code);
        r.put("reason", reason);
        if (unexplained != null) r.put("unexplained", new ArrayList<Object>(unexplained));
        return r;
    }

    private static final List<String> SURFACES = Arrays.asList("narrower", "equal", "wider", "unknown");

    /**
     * May the candidate be promoted? {@code o} = {shadow_digest, enforced_digest, minSamples, principals, explanations?, surface, approval?}.
     * Returns {ok:true, samples, widenings, surface} or {ok:false, code, reason, unexplained?}. Fails closed on any evaluation error.
     */
    public static Map<String, Object> promotionGate(ShadowLog log, Map<String, Object> o) {
        try {
            Object ms = o.get("minSamples");
            if (!Sig.isStr(o.get("shadow_digest"), 128) || !Sig.isStr(o.get("enforced_digest"), 128) || !Sig.isSafeInt(ms) || Json.asLong(ms) < 1
                || !(o.get("principals") instanceof List) || !(o.get("surface") instanceof String) || !SURFACES.contains(o.get("surface"))) return no("bad_input", "bad gate options", null);
            String shadow = (String) o.get("shadow_digest"), enforced = (String) o.get("enforced_digest");
            List<Object> principals = Sig.list(o.get("principals"));
            Stats s = log.stats(shadow);
            if (s.total < Json.asLong(ms)) return no("too_few_samples", s.total + " observation(s), need " + Json.asLong(ms), null);
            if (s.errors > 0) return no("shadow_errors", s.errors + " observation(s) where the candidate failed", null);
            List<Map<String, Object>> diffs = log.diffs(shadow);
            for (Map<String, Object> d : diffs) {
                if (!(verifyShadowDiff(d, log.signer()) && shadow.equals(d.get("shadow_digest")) && enforced.equals(d.get("enforced_digest")))) return no("bad_diff", "a recorded diff does not verify, belongs to another pair, or is missing", null);
            }
            if (diffs.size() != s.diverged) return no("bad_diff", "a recorded diff does not verify, belongs to another pair, or is missing", null);
            Set<Object> explained = new LinkedHashSet<>();
            Object ex = o.get("explanations");
            if (ex != null && !(ex instanceof List) && !(ex instanceof String)) return no("bad_input", "evaluation error (fail closed)", null);
            if (ex instanceof List) {
                for (Object e : (List<?>) ex) if (verifyExplanation(e) && principals.contains(Sig.map(e).get("principal")) && shadow.equals(Sig.map(e).get("shadow_digest"))) explained.add(Sig.map(e).get("action_digest"));
            }
            Set<String> un = new LinkedHashSet<>();
            long widenings = 0;
            for (Map<String, Object> d : diffs) {
                if (Boolean.TRUE.equals(d.get("widening"))) {
                    widenings++;
                    if (!explained.contains(d.get("action_digest"))) un.add((String) d.get("action_digest"));
                }
            }
            if (!un.isEmpty()) {
                List<String> sorted = new ArrayList<>(un);
                Collections.sort(sorted);
                return no("unexplained_widening", sorted.size() + " widening(s) without a principal's explanation", sorted);
            }
            String surface = (String) o.get("surface");
            if (surface.equals("wider") || surface.equals("unknown")) {
                Object a = o.get("approval");
                if (!verifyApproval(a) || !principals.contains(Sig.map(a).get("principal")) || !shadow.equals(Sig.map(a).get("shadow_digest")) || !enforced.equals(Sig.map(a).get("enforced_digest")))
                    return no("advisory_wider", "the analyzer reports the candidate " + (surface.equals("wider") ? "wider" : "not provably narrower") + " on the declared surfaces: a principal-signed approval is required", null);
            }
            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("ok", true);
            ok.put("samples", s.total);
            ok.put("widenings", widenings);
            ok.put("surface", surface);
            return ok;
        } catch (RuntimeException e) {
            return no("bad_input", "evaluation error (fail closed)", null);
        }
    }

    /**
     * The body of the bundle revision that makes the candidate the enforced policy: the candidate's content at revision + 1 chained to the
     * enforced revision with the shadow list cleared. Needs a passing gate and the candidate listed in the enforced revision's shadow.
     */
    public static Map<String, Object> promoteShadow(Map<String, Object> enforced, Map<String, Object> candidate, Map<String, Object> gate, Object now) {
        String digest = Bundle.bundleDigest(candidate);
        if (digest == null) throw new IllegalArgumentException("promoteShadow: unhashable candidate");
        if (!Boolean.TRUE.equals(gate.get("ok"))) throw new IllegalArgumentException("promoteShadow: the gate did not pass (" + gate.get("code") + ")");
        Object sh = enforced.get("shadow");
        if (!(sh instanceof List) || !((List<?>) sh).contains(digest)) throw new IllegalArgumentException("promoteShadow: the candidate is not listed in the enforced revision's shadow");
        if (!Sig.isSafeInt(now)) throw new IllegalArgumentException("promoteShadow: bad time");
        if (!Json.isSafeInt(enforced.get("revision"))) throw new IllegalArgumentException("promoteShadow: bad revision");
        Map<String, Object> out = new LinkedHashMap<>(candidate);
        out.remove("sigs");
        out.remove("shadow");
        out.remove("prev");
        out.put("revision", Json.asLong(enforced.get("revision")) + 1);
        out.put("prev", Bundle.bundleDigest(enforced));
        out.put("issued_at", Json.asLong(now));
        return out;
    }
}
