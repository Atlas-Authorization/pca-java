package net.atlasauth.pca;

import static net.atlasauth.pca.Workflow.ID_RE;
import static net.atlasauth.pca.Workflow.isB32;
import static net.atlasauth.pca.Workflow.isObj;
import static net.atlasauth.pca.Workflow.isStr;
import static net.atlasauth.pca.Workflow.isUint;
import static net.atlasauth.pca.Workflow.l;
import static net.atlasauth.pca.Workflow.m;
import static net.atlasauth.pca.Workflow.onlyKeys;
import static net.atlasauth.pca.Workflow.re;
import static net.atlasauth.pca.Workflow.sortedUnique;
import static net.atlasauth.pca.Workflow.verifyBody;

import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Tokenisation vault and aggregate read limits (K5, C-315..C-319). Companion of {@link ReadSide}. Ports
 * packages/pca/src/read-vault.ts check for check (verification only: grants are signed elsewhere) and replays
 * packages/pca/conformance/vault-aggregate-vectors.json. Total, strict, integers only: a float, a boolean or a string where an
 * integer is required is not an integer. No entry point throws.
 *
 * <p>The aggregate noise is an INTEGER-EXACT discrete Laplace sampler (Canonne, Kamath, Steinke 2020, Alg. 1-2) over a stream of
 * 48-bit draws taken from SHA-256 blocks. Every intermediate value stays below 2^53, so signed 64-bit arithmetic is exact. In
 * {@code seeded} mode the stream is keyed by the salt and the query digest (the shared vectors pin it); in {@code secure} mode
 * (the PRODUCTION setting) it is keyed by a fresh 32-byte seed from the OS CSPRNG.
 */
public final class ReadVault {
    private ReadVault() {}

    // ---- vault ----

    /** What the vault remembers about one minted token. */
    public static final class Entry {
        public final String cls;
        public final Object value;
        public final String grant;
        public final long exp;
        public Entry(String cls, Object value, String grant, long exp) { this.cls = cls; this.value = value; this.grant = grant; this.exp = exp; }
    }

    public interface VaultStore {
        void put(String token, Entry e);
        /** The entry, or null when the token is unknown. */
        Entry get(String token);
    }

    public static VaultStore memoryVault() {
        Map<String, Entry> mm = new ConcurrentHashMap<>();
        return new VaultStore() {
            @Override public void put(String token, Entry e) { mm.put(token, e); }
            @Override public Entry get(String token) { return token == null ? null : mm.get(token); }
        };
    }

    /** {@link ReadSide#redactRead} that also records every token it minted in {@code store}. Never throws. */
    public static ReadSide.Read redactReadWithVault(Object grant, Object principal, Object now, Object verb, Object resource, Object purpose, Object schema,
                                                    Object record, Object tighten, Object salt, Object counts, VaultStore store) {
        try {
            ReadSide.Read r = ReadSide.redactRead(grant, principal, now, verb, resource, purpose, schema, record, tighten, salt, counts);
            if (!"allow".equals(r.decision)) return r;
            Map<String, Object> body = m(m(grant).get("body"));
            String digest = ReadSide.readGrantDigest(body);
            long exp = Json.asLong(body.get("expires_at"));
            for (Map.Entry<String, ReadSide.Field> e : r.fields.entrySet()) {
                ReadSide.Field f = e.getValue();
                if ("masked".equals(f.action) && "token".equals(f.kind)) {
                    Object raw = m(record).get(e.getKey());
                    store.put((String) r.view.get(e.getKey()), new Entry(f.cls, raw instanceof Json.Num ? (Object) Json.asLong(raw) : raw, digest, exp));
                }
            }
            return r;
        } catch (RuntimeException | StackOverflowError e) {
            return new ReadSide.Read("deny", "bad_request", new LinkedHashMap<>(), new LinkedHashMap<>(), new java.util.ArrayList<>(), new LinkedHashMap<>());
        }
    }

    /** Verdict of {@link #detokenize}: {@code value} is the original value on an allow, else null. */
    public static final class Detok {
        public final String decision, code;
        public final Object value;
        Detok(String decision, String code, Object value) { this.decision = decision; this.code = code; this.value = value; }
        public Map<String, Object> toMap() {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("decision", decision); o.put("code", code); o.put("value", value);
            return o;
        }
    }

    private static Detok no(String code) { return new Detok("deny", code, null); }

    /** Turn a token back into its value, only for a sink the grant allows that token's class to reach. Never throws. */
    public static Detok detokenize(Object grant, Object principal, Object now, Object sink, Object token, VaultStore store) {
        try {
            if (!isB32(principal) || !isUint(now) || !(token instanceof String) || !(sink instanceof String)) return no("bad_request");
            ReadSide.Graded g = ReadSide.gradeGrant(grant, principal, now);
            if (g.code != null) return no(g.code);
            Entry e = store.get((String) token);
            if (e == null || !e.grant.equals(ReadSide.readGrantDigest(g.body))) return no("unknown_token");
            if (Json.asLong(now) >= e.exp) return no("expired");
            Object rule = m(g.body.get("sinks")).get(sink);
            if (rule == null) return no("unknown_sink");
            if (l(m(rule).get("allow")).contains(e.cls)) return new Detok("allow", null, e.value);
            if (l(m(rule).get("escalate")).contains(e.cls)) return new Detok("escalate", "label_escalate", null);
            return no("label_flow");
        } catch (RuntimeException | StackOverflowError ex) {
            return no("bad_request");
        }
    }

    // ---- aggregates ----

    public static final String AGGREGATE_DOMAIN = "atlas-pca/aggregate-grant/v1\u0000";
    private static final String AG_REF = "atlas-pca/aggregate-grant-ref/v1";
    private static final String AG_Q = "atlas-pca/aggregate-query/v1";
    private static final String AG_N = "atlas-pca/aggregate-noise/v1";
    private static final Pattern FN_RE = Pattern.compile("(count|sum)");
    private static final List<String> RULE_KEYS = List.of("verb", "resource_prefix", "purposes", "fns", "min_group", "clamp", "epsilon_micro", "dp");
    private static final List<String> BODY_KEYS = List.of("v", "id", "principal", "issued_at", "expires_at", "rules", "epsilon_budget_micro", "max_queries");

    private static Map<String, Object> dm(String d, Object... kv) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("d", d);
        for (int i = 0; i < kv.length; i += 2) o.put((String) kv[i], kv[i + 1]);
        return o;
    }

    private static boolean validRule(Object o) {
        if (!isObj(o) || !onlyKeys(o, RULE_KEYS)) return false;
        Map<String, Object> r = m(o);
        if (!isStr(r.get("verb"), 128) || !isStr(r.get("resource_prefix"), 512) || !sortedUnique(r.get("purposes"), ID_RE, 16) || l(r.get("purposes")).isEmpty()) return false;
        if (!sortedUnique(r.get("fns"), FN_RE, 2) || l(r.get("fns")).isEmpty()) return false;
        if (!isUint(r.get("min_group")) || Json.asLong(r.get("min_group")) < 1) return false;
        if (!isUint(r.get("clamp")) || Json.asLong(r.get("clamp")) > 1_000_000L) return false;
        if (!isUint(r.get("epsilon_micro")) || Json.asLong(r.get("epsilon_micro")) > 1_073_741_824L) return false;
        Object dp = r.get("dp");
        return dp instanceof Boolean && (!((Boolean) dp) || Json.asLong(r.get("epsilon_micro")) >= 1);
    }

    /** Shape of an aggregate grant body (no signature). */
    public static boolean validAggregateGrantBody(Object o) {
        if (!isObj(o) || !onlyKeys(o, BODY_KEYS)) return false;
        Map<String, Object> b = m(o);
        if (!Json.isSafeInt(b.get("v")) || Json.asLong(b.get("v")) != 1) return false;
        if (!re(ID_RE, b.get("id")) || !isB32(b.get("principal")) || !isUint(b.get("issued_at")) || !isUint(b.get("expires_at"))) return false;
        if (!(b.get("rules") instanceof List) || l(b.get("rules")).isEmpty() || l(b.get("rules")).size() > 16) return false;
        for (Object r : l(b.get("rules"))) if (!validRule(r)) return false;
        return isUint(b.get("epsilon_budget_micro")) && isUint(b.get("max_queries"));
    }

    public static String aggregateGrantDigest(Object body) { return Pca.hashCanonical(dm(AG_REF, "g", body)); }

    /** The explicit state an aggregate read steps over (the input is never mutated). */
    public static final class State {
        public final long spentMicro, queries;
        public final Map<String, Long> answered;
        State(long spentMicro, long queries, Map<String, Long> answered) { this.spentMicro = spentMicro; this.queries = queries; this.answered = answered; }
        public static State empty() { return new State(0, 0, new LinkedHashMap<>()); }
        /** Plain-map form {spent_micro, queries, answered} (integers as Long); {@link #aggregateRead} accepts it back. */
        public Map<String, Object> toMap() {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("spent_micro", spentMicro); o.put("queries", queries); o.put("answered", new LinkedHashMap<String, Object>(answered));
            return o;
        }
    }

    /** The state from its map form, or null when malformed. */
    private static State parseState(Object o) {
        if (!isObj(o)) return null;
        Map<String, Object> s = m(o);
        if (!isUint(s.get("spent_micro")) || !isUint(s.get("queries")) || !isObj(s.get("answered"))) return null;
        Map<String, Long> ans = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : m(s.get("answered")).entrySet()) {
            if (!Json.isSafeInt(e.getValue())) return null;
            ans.put(e.getKey(), Json.asLong(e.getValue()));
        }
        return new State(Json.asLong(s.get("spent_micro")), Json.asLong(s.get("queries")), ans);
    }

    public static final class Aggregate {
        public final String decision, code;
        public final Long value;
        public final State state;
        public final long chargedMicro;
        Aggregate(String decision, String code, Long value, State state, long chargedMicro) { this.decision = decision; this.code = code; this.value = value; this.state = state; this.chargedMicro = chargedMicro; }
        public Map<String, Object> toMap() {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("decision", decision); o.put("code", code); o.put("value", value); o.put("state", state.toMap()); o.put("charged_micro", chargedMicro);
            return o;
        }
    }

    private static Aggregate refuse(String code, State s) { return new Aggregate("deny", code, null, s, 0); }

    private static long clamp(long v, long c) { return Math.max(-c, Math.min(c, v)); }

    /**
     * Answer one aggregate under the grant, or refuse. {@code values} is one integer per row (for {@code count} only the number of
     * rows matters), {@code state} the map form of a {@link State}, {@code fn} "count" or "sum", {@code noise} "seeded" (deterministic from
     * the salt and the query) or "secure" (OS CSPRNG: PRODUCTION; the answer is then not reproducible). A refusal returns the input
     * state unchanged, except a malformed state or an internal error, which return the empty state. Never throws.
     */
    public static Aggregate aggregateRead(Object grant, Object principal, Object now, Object verb, Object resource, Object purpose, Object fn,
                                          Object values, Object salt, Object noise, Object state) {
        try {
            State st = parseState(state);
            if (st == null) return refuse("bad_request", State.empty());
            if (!isB32(principal) || !isUint(now)) return refuse("bad_request", st);
            if (!isObj(grant) || !onlyKeys(grant, List.of("body", "sig")) || !validAggregateGrantBody(m(grant).get("body"))) return refuse("bad_grant", st);
            Map<String, Object> g = m(m(grant).get("body"));
            if (!principal.equals(g.get("principal")) || !verifyBody(AGGREGATE_DOMAIN, g, principal, m(grant).get("sig"))) return refuse("bad_signature", st);
            long n = Json.asLong(now);
            if (n < Json.asLong(g.get("issued_at"))) return refuse("not_yet", st);
            if (n >= Json.asLong(g.get("expires_at"))) return refuse("expired", st);
            if (!isStr(verb, 128) || !isStr(resource, 512) || !re(ID_RE, purpose) || !("count".equals(fn) || "sum".equals(fn)) || !("seeded".equals(noise) || "secure".equals(noise))
                || !(salt instanceof String) || ((String) salt).length() < 16 || !(values instanceof List) || l(values).size() > 1_000_000) return refuse("bad_request", st);
            long[] vs = new long[l(values).size()];
            for (int i = 0; i < vs.length; i++) {
                Object v = l(values).get(i);
                if (!Json.isSafeInt(v)) return refuse("bad_request", st);
                vs[i] = Json.asLong(v);
            }
            Map<String, Object> rule = null;
            for (Object ro : l(g.get("rules"))) {
                Map<String, Object> r = m(ro);
                if (r.get("verb").equals(verb) && ((String) resource).startsWith((String) r.get("resource_prefix")) && l(r.get("purposes")).contains(purpose)) { rule = r; break; }
            }
            if (rule == null || !l(rule.get("fns")).contains(fn)) return refuse("no_read_scope", st);
            if (vs.length < Json.asLong(rule.get("min_group"))) return refuse("group_too_small", st);
            long clampV = Json.asLong(rule.get("clamp"));
            long clampedSum = 0;
            for (long v : vs) clampedSum += clamp(v, clampV);
            String qd = Pca.hashCanonical(dm(AG_Q, "g", aggregateGrantDigest(g), "verb", verb, "resource", resource, "purpose", purpose, "fn", fn, "n", (long) vs.length, "s", clampedSum));
            Long prior = st.answered.get(qd);
            if (prior != null) return new Aggregate("allow", null, prior, st, 0);
            if (st.queries + 1 > Json.asLong(g.get("max_queries"))) return refuse("query_cap", st);
            boolean dp = Boolean.TRUE.equals(rule.get("dp"));
            long eps = Json.asLong(rule.get("epsilon_micro"));
            long cost = dp ? eps : 0;
            if (st.spentMicro + cost > Json.asLong(g.get("epsilon_budget_micro"))) return refuse("epsilon_exhausted", st);
            long exact = "count".equals(fn) ? vs.length : clampedSum;
            if (dp) {
                long sens = "count".equals(fn) ? 1 : clampV;
                Draws draws = "secure".equals(noise) ? secureDraws() : seededDraws(Pca.hashCanonical(dm(AG_N, "salt", salt, "q", qd)));
                exact += discreteLaplace(draws, eps, Math.multiplyExact(sens, 1_000_000L));
            }
            Map<String, Long> ans = new LinkedHashMap<>(st.answered);
            ans.put(qd, exact);
            return new Aggregate("allow", null, exact, new State(st.spentMicro + cost, st.queries + 1, ans), cost);
        } catch (RuntimeException | StackOverflowError e) { // includes the sampler's "bad bound" / "no termination" errors
            return refuse("bad_request", State.empty());
        }
    }

    // ---- integer-exact discrete Laplace sampler (CKS 2020, Alg. 1-2) ----
    // P[noise = x] is proportional to exp(-|x| * epsilon / sensitivity) with epsilon = epsilon_micro / 1e6.

    private static final String DP_STREAM = "atlas-pca/dp-stream/v1";
    private static final long TWO48 = 1L << 48;
    private static final int MAX_STEPS = 100_000;

    public interface Draws {
        /** A uniform value in [0, n), 1 &lt;= n &lt;= 2^47; IllegalArgumentException on a bad bound or no draw. */
        long uniform(long n);
    }

    /** A draw source: block i is SHA-256 of the canonical {d, seed, i}; each block yields five 48-bit big-endian values (bytes 0-5, 6-11, ...). */
    public static Draws seededDraws(String seed) {
        return new Draws() {
            private long block = 0;
            private final long[] buf = new long[5];
            private int pos = 5;

            private long next48() {
                if (pos == 5) {
                    byte[] bytes = Pca.decodeB64uStrict(Pca.hashCanonical(dm(DP_STREAM, "seed", seed, "i", block++)), 32);
                    for (int k = 0; k < 5; k++) {
                        long v = 0;
                        for (int j = 0; j < 6; j++) v = v * 256 + (bytes[k * 6 + j] & 0xffL);
                        buf[k] = v;
                    }
                    pos = 0;
                }
                return buf[pos++];
            }

            @Override public long uniform(long n) {
                if (n < 1 || n > (1L << 47)) throw new IllegalArgumentException("uniform: bad bound");
                long limit = TWO48 - (TWO48 % n);
                for (int i = 0; i < MAX_STEPS; i++) {
                    long r = next48();
                    if (r < limit) return r % n;
                }
                throw new IllegalArgumentException("uniform: no draw");
            }
        };
    }

    /** The PRODUCTION mode: a seed from the operating system's CSPRNG. Answers differ per call; a repeated query is still answered from the state. */
    public static Draws secureDraws() {
        byte[] b = new byte[32];
        new SecureRandom().nextBytes(b);
        return seededDraws(Pca.b64(b));
    }

    private static boolean bern(Draws d, long num, long den) { return d.uniform(den) < num; } // Bernoulli(num/den)

    /** Bernoulli(exp(-num/den)) for 0 &lt;= num/den &lt;= 1. */
    private static boolean bernExpSmall(Draws d, long num, long den) {
        for (long k = 1; k <= MAX_STEPS; k++) if (!bern(d, num, Math.multiplyExact(den, k))) return k % 2 == 1;
        throw new IllegalArgumentException("bernoulli: no termination");
    }

    /** Discrete Laplace with P[x] proportional to exp(-|x| s / t) (CKS Alg. 2: s is the rate numerator, t the scale denominator). */
    public static long discreteLaplace(Draws d, long s, long t) {
        if (s < 1) throw new IllegalArgumentException("laplace: bad rate");
        for (int outer = 0; outer < MAX_STEPS; outer++) {
            long u = d.uniform(t);
            if (!bernExpSmall(d, u, t)) continue;
            long v = 0;
            while (bernExpSmall(d, 1, 1)) if (++v > MAX_STEPS) throw new IllegalArgumentException("laplace: no termination");
            long y = Math.addExact(u, Math.multiplyExact(t, v)) / s;
            boolean negative = d.uniform(2) == 1;
            if (negative && y == 0) continue;
            return negative ? -y : y;
        }
        throw new IllegalArgumentException("laplace: no sample");
    }
}
