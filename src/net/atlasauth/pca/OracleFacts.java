package net.atlasauth.pca;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Rule 16: intent world facts, relational dimensions and offer sets (packages/pca/src/oracle-facts.ts
 * {@code decideIntentWorld} and offer-set.ts {@code decideOfferSet}). The verifier computes {@code env.world}; the agent
 * only commits the artifacts ({@code intent_session.facts} / {@code offer_set}). First failure wins, every failure is
 * {@code ok: false}; never throws.
 */
public final class OracleFacts {
    private OracleFacts() {}

    public static final String FACT_DOMAIN = "atlas-pca/fact/v1\0";
    public static final String FACT_REF_DOMAIN = "atlas-pca/fact-ref/v1";
    public static final String OFFER_SET_DOMAIN = "atlas-pca/offer-set/v1\0";
    public static final String OFFER_SET_REF_DOMAIN = "atlas-pca/offer-set-ref/v1";
    public static final int MAX_COMMITTED_FACTS = 16;
    public static final int MAX_WORLDS = 16;
    public static final int MAX_RELATIONAL = 16;
    public static final long DEFAULT_WORLD_SKEW_MS = 60_000L;
    public static final int MAX_OFFERS = 256;
    public static final int MAX_OFFER_ATTRS = 32;
    public static final int MAX_QUERY_KEYS = 32;
    private static final BigInteger MAX_SAFE_BIG = BigInteger.valueOf(9007199254740991L);

    /** The rule-16 verdict: {@code world} (world names, then relational names, then the offers name) and {@code singleSource}. */
    public static final class WorldResult {
        public final boolean ok;
        public final String reason;
        public final Map<String, Object> world;
        public final List<String> singleSource;
        WorldResult(boolean ok, String reason, Map<String, Object> world, List<String> singleSource) {
            this.ok = ok; this.reason = reason; this.world = world; this.singleSource = singleSource;
        }
        static WorldResult fail(String reason) { return new WorldResult(false, "facts: " + reason, null, null); }
    }

    // ---- wire ----
    static String validateFactWire(Object fo) {
        if (!(fo instanceof Map)) return "fact must be an object";
        Map<String, Object> f = IntentJs.obj(fo);
        String m = IntentArtifacts.closedMembers(f, List.of("v", "kind", "name", "subject", "value", "t_obs", "oracle", "sig"), IntentArtifacts.SUITE_MEMBERS, "fact");
        if (m != null) return m;
        if (!isOne(f.get("v")) || !"pca-fact".equals(f.get("kind"))) return "fact must be {v: 1, kind: \"pca-fact\"}";
        if (!IntentArtifacts.isName(f.get("name"))) return "'fact.name' must match ^[a-z][a-z0-9_]{0,63}$";
        if (!IntentArtifacts.isBoundedString(f.get("subject"), 256)) return "'fact.subject' must be a non-empty string (<= 256 bytes)";
        if (!IntentJs.isInt(f.get("value")) && !IntentArtifacts.isBoundedString(f.get("value"), 256)) return "'fact.value' must be a safe integer or a non-empty string (<= 256 bytes)";
        if (!IntentJs.isInt(f.get("t_obs")) || IntentJs.num(f.get("t_obs")) < 0) return "'fact.t_obs' must be a non-negative safe integer";
        if (!IntentArtifacts.isBoundedString(f.get("oracle"), 64)) return "'fact.oracle' must be a non-empty string (<= 64 bytes)";
        if (!(f.get("sig") instanceof String)) return "'fact.sig' must be a string";
        return null;
    }

    /** {@code x === 1} for a JSON number. */
    static boolean isOne(Object v) { Double d = IntentJs.num(v); return d != null && d == 1.0; }

    public static String factRef(Map<String, Object> f) { return IntentArtifacts.artifactRef(FACT_REF_DOMAIN, "f", f); }
    public static String offerSetRef(Map<String, Object> o) { return IntentArtifacts.artifactRef(OFFER_SET_REF_DOMAIN, "o", o); }

    static Long ratioPpm(long a, long b) {
        if (!(b > 0) || a < 0) return null;
        BigInteger q = BigInteger.valueOf(a).multiply(BigInteger.valueOf(1_000_000L)).divide(BigInteger.valueOf(b));
        return q.compareTo(MAX_SAFE_BIG) <= 0 ? q.longValue() : null;
    }

    /** A non-empty ARRAY (strict typing: nothing else makes a check active). */
    static boolean nonEmpty(Object x) { return x instanceof List && !((List<?>) x).isEmpty(); }

    // ---- policy ----
    static String validateWorldPolicy(Object po) {
        if (!(po instanceof Map)) return "world policy must be an object";
        Map<String, Object> p = IntentJs.obj(po);
        String cm = IntentArtifacts.closedMembers(p, List.of(), List.of("skew_ms", "worlds", "relational", "offers"), "policy");
        if (cm != null) return cm;
        if (p.containsKey("skew_ms") && (!IntentJs.isInt(p.get("skew_ms")) || IntentJs.num(p.get("skew_ms")) < 0)) return "skew_ms must be a non-negative safe integer";
        Set<String> names = new HashSet<>();
        Object worldsO = IntentJs.opt(p, "worlds", List.of());
        if (!(worldsO instanceof List) || ((List<?>) worldsO).size() > MAX_WORLDS) return "worlds must be a list of at most " + MAX_WORLDS;
        for (Object wo : (List<?>) worldsO) {
            if (!(wo instanceof Map)) return "world entry must be an object";
            Map<String, Object> w = IntentJs.obj(wo);
            String wm = IntentArtifacts.closedMembers(w, List.of("name", "subject_path", "oracles", "freshness_ms", "min_oracles", "max_faulty"), List.of(), "world");
            if (wm != null) return wm;
            String e = claim(names, w.get("name"));
            if (e != null) return e;
            String n = String.valueOf(w.get("name"));
            if (!(w.get("subject_path") instanceof String) || !((String) w.get("subject_path")).startsWith("action.")) return "world '" + n + "': subject_path must be rooted at action.";
            if (!IntentJs.isInt(w.get("freshness_ms")) || IntentJs.num(w.get("freshness_ms")) < 0) return "world '" + n + "': freshness_ms must be a non-negative safe integer";
            if (!IntentJs.isInt(w.get("max_faulty")) || IntentJs.num(w.get("max_faulty")) < 0) return "world '" + n + "': max_faulty must be a non-negative safe integer";
            if (!IntentJs.isInt(w.get("min_oracles")) || IntentJs.num(w.get("min_oracles")) < 2 * IntentJs.num(w.get("max_faulty")) + 1)
                return "world '" + n + "': min_oracles must be a safe integer >= 2*max_faulty+1";
            if (!(w.get("oracles") instanceof List) || ((List<?>) w.get("oracles")).size() < IntentJs.num(w.get("min_oracles"))) return "world '" + n + "': fewer pinned oracles than min_oracles";
            Set<String> kids = new HashSet<>();
            for (Object o : (List<?>) w.get("oracles")) {
                if (!(o instanceof Map) || IntentArtifacts.closedMembers(IntentJs.obj(o), List.of("kid", "pk"), List.of("pq_pk"), "oracle") != null
                    || !IntentArtifacts.isBoundedString(((Map<?, ?>) o).get("kid"), 64) || !IntentArtifacts.isDigest(((Map<?, ?>) o).get("pk"))
                    || !IntentArtifacts.pinPqOk(o) || kids.contains((String) ((Map<?, ?>) o).get("kid")))
                    return "world '" + n + "': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk";
                kids.add((String) ((Map<?, ?>) o).get("kid"));
            }
        }
        Object relO = IntentJs.opt(p, "relational", List.of());
        if (!(relO instanceof List) || ((List<?>) relO).size() > MAX_RELATIONAL) return "relational must be a list of at most " + MAX_RELATIONAL;
        for (Object ro : (List<?>) relO) {
            if (!(ro instanceof Map)) return "relational entry must be an object";
            Map<String, Object> r = IntentJs.obj(ro);
            String rm = IntentArtifacts.closedMembers(r, List.of("name", "fn", "a", "b"), List.of(), "relational");
            if (rm != null) return rm;
            String e = claim(names, r.get("name"));
            if (e != null) return e;
            String n = (String) r.get("name");
            if (!"sub".equals(r.get("fn")) && !"ratio_ppm".equals(r.get("fn"))) return "relational '" + n + "': fn must be \"sub\" or \"ratio_ppm\"";
            for (Object op : new Object[] {r.get("a"), r.get("b")}) {
                boolean ok = IntentArtifacts.isParamPath(op);
                if (!ok && op instanceof String && ((String) op).startsWith("env.world.")) {
                    String rest = ((String) op).substring("env.world.".length());
                    ok = names.contains(rest) && !rest.equals(n);
                }
                if (!ok) return "relational '" + n + "': operand '" + op + "' must be an action.params path or an earlier env.world dimension";
            }
        }
        if (p.containsKey("offers")) {
            String e = validateOfferPolicy(p.get("offers"));
            if (e == null) e = claim(names, ((Map<?, ?>) p.get("offers")).get("name"));
            if (e != null) return e;
        }
        return null;
    }

    private static String claim(Set<String> names, Object n) {
        if (!IntentArtifacts.isName(n)) return "dimension name '" + n + "' must match ^[a-z][a-z0-9_]{0,63}$";
        if (names.contains(n)) return "duplicate dimension name '" + n + "'";
        names.add((String) n);
        return null;
    }

    static String validateOfferPolicy(Object po) {
        if (!(po instanceof Map)) return "offers policy must be an object";
        Map<String, Object> p = IntentJs.obj(po);
        String cm = IntentArtifacts.closedMembers(p, List.of("name", "site_keys", "max_age_ms", "offer_param", "filter"), List.of(), "offers");
        if (cm != null) return cm;
        if (!(p.get("name") instanceof String)) return "offers policy needs a name";
        if (!(p.get("site_keys") instanceof List) || ((List<?>) p.get("site_keys")).isEmpty()) return "offers policy needs at least one pinned site key";
        Set<String> kids = new HashSet<>();
        for (Object k : (List<?>) p.get("site_keys")) {
            if (!(k instanceof Map) || IntentArtifacts.closedMembers(IntentJs.obj(k), List.of("kid", "pk"), List.of("pq_pk"), "site_key") != null
                || !IntentArtifacts.isBoundedString(((Map<?, ?>) k).get("kid"), 64) || !IntentArtifacts.isDigest(((Map<?, ?>) k).get("pk"))
                || !IntentArtifacts.pinPqOk(k) || kids.contains((String) ((Map<?, ?>) k).get("kid")))
                return "offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk";
            kids.add((String) ((Map<?, ?>) k).get("kid"));
        }
        if (!IntentJs.isInt(p.get("max_age_ms")) || IntentJs.num(p.get("max_age_ms")) < 0) return "offers policy: max_age_ms must be a non-negative safe integer";
        if (!(p.get("offer_param") instanceof String) || !((String) p.get("offer_param")).startsWith("action.params.")) return "offers policy: offer_param must be an action.params.* path";
        Object f = p.get("filter");
        if (!(f instanceof Map) || IntentArtifacts.closedMembers(IntentJs.obj(f), List.of("query", "offer"), List.of(), "filter") != null
            || !(((Map<?, ?>) f).get("query") instanceof Map) || !(((Map<?, ?>) f).get("offer") instanceof Map)) return "offers policy: filter must be exactly {query: {}, offer: {}}";
        for (Object v : ((Map<?, ?>) ((Map<?, ?>) f).get("query")).values()) if (!IntentArtifacts.isScalar(v)) return "offers policy: filter values must be scalars";
        for (Object v : ((Map<?, ?>) ((Map<?, ?>) f).get("offer")).values()) if (!IntentArtifacts.isScalar(v)) return "offers policy: filter values must be scalars";
        return null;
    }

    /**
     * True iff rule 16 is active: {@code facts} a non-empty array, {@code offer_set} a string, {@code worlds} /
     * {@code relational} a non-empty array, or {@code offers} a plain object.
     */
    public static boolean intentWorldActive(Object committed, Object policy) {
        if (!(committed instanceof Map)) committed = Map.of();
        if (!(policy instanceof Map)) policy = Map.of();
        return nonEmpty(IntentJs.get(committed, "facts")) || IntentJs.get(committed, "offer_set") instanceof String
            || nonEmpty(IntentJs.get(policy, "worlds")) || nonEmpty(IntentJs.get(policy, "relational")) || IntentJs.get(policy, "offers") instanceof Map;
    }

    /** {@code o.k} with JavaScript semantics: a property read on null / undefined throws. */
    private static Object prop(Object o, String k) {
        if (o == null) throw new IllegalArgumentException("cannot read '" + k + "' of null");
        return IntentJs.get(o, k);
    }

    private static String subjectOf(Object action, String path) {
        if (path.equals("action.resource")) { Object r = prop(action, "resource"); return r instanceof String ? (String) r : null; }
        if (path.equals("action.verb")) { Object v = prop(action, "verb"); return v instanceof String ? (String) v : null; }
        if (action == null) throw new IllegalArgumentException("no action");
        Predicates.Resolved r = IntentArtifacts.resolveParamPath(IntentArtifacts.actionParams(action), path);
        return r.found && r.value instanceof String ? (String) r.value : null;
    }

    /** The {@code primitives.intent_world} entry point: normalizes {@code input}, then {@link #decide}. */
    public static WorldResult decideIntentWorld(Object input) {
        try {
            return decide(IntentJs.obj(IntentJs.normalize(input)));
        } catch (RuntimeException e) {
            return WorldResult.fail("evaluation error (fail closed): " + e.getClass().getSimpleName());
        }
    }

    /** Rule 16 over an already normalized input {@code {now, aud, session, action, committed, facts?, offer_set?, policy}}. */
    static WorldResult decide(Map<String, Object> input) {
        try {
            Object policyO = IntentJs.opt(input, "policy", new LinkedHashMap<String, Object>());
            String pe = validateWorldPolicy(policyO);
            if (pe != null) return WorldResult.fail("policy misconfigured (fail closed): " + pe);
            Map<String, Object> policy = IntentJs.obj(policyO);
            // CLOCK: a `now` that is not a safe integer is never coerced: every fact and every offer set is stale
            boolean clock = IntentJs.isInt(input.get("now"));
            double now = clock ? IntentJs.num(input.get("now")) : Double.NaN;
            double skew = policy.containsKey("skew_ms") ? IntentJs.num(policy.get("skew_ms")) : DEFAULT_WORLD_SKEW_MS;
            if (!(input.get("action") instanceof Map)) return WorldResult.fail("action must be an object");
            if (!(IntentJs.opt(input.get("action"), "params", Map.of()) instanceof Map)) return WorldResult.fail("action.params must be an object");
            Object committed = IntentJs.opt(input, "committed", new LinkedHashMap<String, Object>());
            if (!(committed instanceof Map)) return WorldResult.fail("committed must be an object");
            Object committedFacts = IntentJs.opt(committed, "facts", List.of());
            if (!(committedFacts instanceof List) || ((List<?>) committedFacts).size() > MAX_COMMITTED_FACTS)
                return WorldResult.fail("committed facts must be a list of at most " + MAX_COMMITTED_FACTS + " digests");
            Set<String> seen = new HashSet<>();
            for (Object d : (List<?>) committedFacts) {
                if (!IntentArtifacts.isDigest(d)) return WorldResult.fail("a committed fact digest is not canonical base64url (32 bytes)");
                if (!seen.add((String) d)) return WorldResult.fail("duplicate committed fact digest");
            }
            boolean offerCommitted = IntentJs.own(committed, "offer_set");
            Object committedOffer = IntentJs.get(committed, "offer_set");
            if (offerCommitted && !IntentArtifacts.isDigest(committedOffer)) return WorldResult.fail("the committed offer_set is not canonical base64url (32 bytes)");

            Object supplied = IntentJs.opt(input, "facts", List.of());
            if (!(supplied instanceof List)) return WorldResult.fail("facts must be an array");
            if (input.containsKey("offer_set") && !(input.get("offer_set") instanceof Map)) return WorldResult.fail("offer_set must be an object");
            Map<String, Map<String, Object>> byRef = new HashMap<>();
            for (Object f : IntentArtifacts.iterable(supplied)) {
                if (validateFactWire(f) != null) continue;
                try { byRef.put(factRef(IntentJs.obj(f)), IntentJs.obj(f)); } catch (RuntimeException e) { /* no reference */ }
            }
            List<?> worlds = (List<?>) IntentJs.opt(policy, "worlds", List.of());
            List<Map<String, Object>> accepted = new ArrayList<>();
            Set<String> pairs = new HashSet<>();
            for (Object d : (List<?>) committedFacts) {
                Map<String, Object> fact = byRef.get(d);
                if (fact == null) return WorldResult.fail("a committed fact was not supplied (or is malformed)");
                String se = IntentArtifacts.artifactSuiteError(fact);
                if (se != null) return WorldResult.fail("fact signature suite: " + se);
                Map<String, Object> w = null;
                for (Object x : worlds) if (fact.get("name").equals(IntentJs.get(x, "name"))) { w = IntentJs.obj(x); break; }
                if (w == null) return WorldResult.fail("fact for undeclared world '" + fact.get("name") + "'");
                Map<String, Object> pin = null;
                for (Object o : (List<?>) w.get("oracles")) if (fact.get("oracle").equals(IntentJs.get(o, "kid"))) { pin = IntentJs.obj(o); break; }
                if (pin == null) return WorldResult.fail("oracle '" + fact.get("oracle") + "' is not pinned for world '" + w.get("name") + "'");
                if (!IntentArtifacts.verifyArtifactSig(FACT_DOMAIN, fact, pin.get("pk"), pin.get("pq_pk"))) return WorldResult.fail("bad oracle signature on a '" + w.get("name") + "' fact");
                String subject = subjectOf(input.get("action"), (String) w.get("subject_path"));
                if (subject == null || !fact.get("subject").equals(subject)) return WorldResult.fail("a '" + w.get("name") + "' fact names another subject");
                String pair = w.get("name") + "\u0000" + fact.get("oracle");
                if (!pairs.add(pair)) return WorldResult.fail("two facts from oracle '" + fact.get("oracle") + "' for world '" + w.get("name") + "'");
                accepted.add(fact);
            }

            Map<String, Object> world = new LinkedHashMap<>();
            List<String> singleSource = new ArrayList<>();
            for (Object wo : worlds) {
                Map<String, Object> w = IntentJs.obj(wo);
                String name = (String) w.get("name");
                double freshness = IntentJs.num(w.get("freshness_ms"));
                List<Map<String, Object>> fresh = new ArrayList<>();
                for (Map<String, Object> f : accepted) {
                    double t = IntentJs.num(f.get("t_obs"));
                    if (clock && name.equals(f.get("name")) && t <= now + skew && now - t <= freshness) fresh.add(f);
                }
                double minOracles = IntentJs.num(w.get("min_oracles"));
                if (fresh.size() < minOracles) return WorldResult.fail("world '" + name + "' has " + fresh.size() + " fresh fact(s), needs " + IntentJs.lng(w.get("min_oracles")));
                List<Long> nums = new ArrayList<>();
                for (Map<String, Object> f : fresh) if (IntentJs.isNumber(f.get("value"))) nums.add(IntentJs.lng(f.get("value")));
                if (nums.size() == fresh.size()) {
                    nums.sort(Long::compare);
                    world.put(name, IntentJs.ofLong(nums.get((nums.size() - 1) / 2)));
                } else if (nums.isEmpty()) {
                    Object v = fresh.get(0).get("value");
                    for (Map<String, Object> f : fresh) if (!v.equals(f.get("value"))) return WorldResult.fail("world '" + name + "': string facts disagree");
                    world.put(name, v);
                } else return WorldResult.fail("world '" + name + "': facts mix integer and string values");
                if (minOracles == 1) singleSource.add(name);
            }

            Object rel = IntentJs.opt(policy, "relational", List.of());
            for (Object ro : (List<?>) rel) {
                Map<String, Object> r = IntentJs.obj(ro);
                Long a = operand(world, input, (String) r.get("a"));
                Long b = operand(world, input, (String) r.get("b"));
                if (a == null || b == null) return WorldResult.fail("relational '" + r.get("name") + "': an operand is missing or not a safe integer");
                Long v = "sub".equals(r.get("fn")) ? Long.valueOf(a - b) : ratioPpm(a, b);
                if (v == null || Math.abs(v) > 9007199254740991L) return WorldResult.fail("relational '" + r.get("name") + "': result undefined or outside the safe integer range");
                world.put((String) r.get("name"), IntentJs.ofLong(v));
            }

            if (policy.containsKey("offers")) {
                Map<String, Object> op = IntentJs.obj(policy.get("offers"));
                Object[] od = decideOfferSet(op, offerCommitted ? (String) committedOffer : null, input.containsKey("offer_set"), input.get("offer_set"),
                    actionParams(input), input.get("aud"), input.get("session"), clock, now, skew);
                if (od[0] instanceof String) return WorldResult.fail((String) od[0]);
                world.put((String) op.get("name"), IntentJs.ofLong((Long) od[1]));
            }
            return new WorldResult(true, null, world, singleSource);
        } catch (RuntimeException e) {
            return WorldResult.fail("evaluation error (fail closed): " + e.getClass().getSimpleName());
        }
    }

    /** {@code input.action.params ?? {}} (reading a member of a missing action throws, like JavaScript). */
    private static Object actionParams(Map<String, Object> input) {
        if (input.get("action") == null) throw new IllegalArgumentException("no action");
        return IntentArtifacts.actionParams(input.get("action"));
    }

    private static Long operand(Map<String, Object> world, Map<String, Object> input, String path) {
        if (path.startsWith("env.world.")) {
            Object v = world.get(path.substring("env.world.".length()));
            return IntentJs.isInt(v) ? IntentJs.lng(v) : null;
        }
        Predicates.Resolved r = IntentArtifacts.resolveParamPath(actionParams(input), path);
        return r.found && IntentJs.isInt(r.value) ? IntentJs.lng(r.value) : null;
    }

    // ---- offer sets ----
    static String validateOfferSetWire(Object oo) {
        if (!(oo instanceof Map)) return "offer set must be an object";
        Map<String, Object> o = IntentJs.obj(oo);
        String m = IntentArtifacts.closedMembers(o, List.of("v", "kind", "site", "session", "query", "rank", "complete", "offers", "issued_at", "kid", "sig"), IntentArtifacts.SUITE_MEMBERS, "offer_set");
        if (m != null) return m;
        if (!isOne(o.get("v")) || !"pca-offer-set".equals(o.get("kind"))) return "offer set must be {v: 1, kind: \"pca-offer-set\"}";
        if (!IntentArtifacts.isBoundedString(o.get("site"), 256)) return "'offer_set.site' must be a non-empty string (<= 256 bytes)";
        if (!IntentArtifacts.isDigest(o.get("session"))) return "'offer_set.session' must be canonical base64url (32 bytes)";
        if (!(o.get("query") instanceof Map) || ((Map<?, ?>) o.get("query")).size() > MAX_QUERY_KEYS) return "'offer_set.query' must be an object with <= " + MAX_QUERY_KEYS + " keys";
        for (Map.Entry<?, ?> e : ((Map<?, ?>) o.get("query")).entrySet())
            if (!IntentArtifacts.isBoundedString(e.getKey(), 64) || !IntentArtifacts.isScalar(e.getValue())) return "'offer_set.query." + e.getKey() + "' must be a scalar";
        if (!"price_asc".equals(o.get("rank"))) return "'offer_set.rank' must be \"price_asc\"";
        if (!(o.get("complete") instanceof Boolean)) return "'offer_set.complete' must be a boolean";
        if (!(o.get("offers") instanceof List) || ((List<?>) o.get("offers")).isEmpty() || ((List<?>) o.get("offers")).size() > MAX_OFFERS)
            return "'offer_set.offers' must hold 1.." + MAX_OFFERS + " offers";
        Set<String> ids = new HashSet<>();
        List<?> offers = (List<?>) o.get("offers");
        for (int i = 0; i < offers.size(); i++) {
            Object of = offers.get(i);
            if (!(of instanceof Map)) return "offer " + i + " must be an object";
            Map<String, Object> x = IntentJs.obj(of);
            if (!IntentArtifacts.isBoundedString(x.get("offer_id"), 128)) return "offer " + i + ": 'offer_id' must be a non-empty string (<= 128 bytes)";
            if (!ids.add((String) x.get("offer_id"))) return "offer " + i + ": duplicate offer_id";
            if (!IntentJs.isInt(x.get("price")) || IntentJs.num(x.get("price")) < 0) return "offer " + i + ": 'price' must be a non-negative safe integer";
            int attrs = 0;
            for (String k : x.keySet()) if (!k.equals("offer_id") && !k.equals("price")) attrs++;
            if (attrs > MAX_OFFER_ATTRS) return "offer " + i + ": more than " + MAX_OFFER_ATTRS + " attributes";
            for (String k : x.keySet()) {
                if (k.equals("offer_id") || k.equals("price")) continue;
                if (!IntentArtifacts.isBoundedString(k, 64) || !IntentArtifacts.isScalar(x.get(k))) return "offer " + i + ": attribute '" + k + "' must be a scalar";
            }
        }
        if (!IntentJs.isInt(o.get("issued_at")) || IntentJs.num(o.get("issued_at")) < 0) return "'offer_set.issued_at' must be a non-negative safe integer";
        if (!IntentArtifacts.isBoundedString(o.get("kid"), 64)) return "'offer_set.kid' must be a non-empty string (<= 64 bytes)";
        if (!(o.get("sig") instanceof String)) return "'offer_set.sig' must be a string";
        return null;
    }

    static boolean offerMatches(Map<?, ?> offer, Map<?, ?> f) {
        for (Map.Entry<?, ?> e : f.entrySet()) if (!offer.containsKey(e.getKey()) || !IntentArtifacts.scalarEq(offer.get(e.getKey()), e.getValue())) return false;
        return true;
    }

    static boolean queryCovers(Map<?, ?> query, Map<?, ?> fq) {
        for (Map.Entry<?, ?> e : query.entrySet()) if (!fq.containsKey(e.getKey()) || !IntentArtifacts.scalarEq(fq.get(e.getKey()), e.getValue())) return false;
        return true;
    }

    /** {@code [reason]} on failure, {@code [null, excess]} on success. */
    static Object[] decideOfferSet(Map<String, Object> policy, String committed, boolean supplied, Object o, Object params, Object aud,
                                   Object session, boolean clock, double now, double skewMs) {
        if (committed == null) return new Object[] {"offers: the PCActn commits no offer set but the policy requires one"};
        if (!supplied) return new Object[] {"offers: the committed offer set was not supplied"};
        String w = validateOfferSetWire(o);
        if (w != null) return new Object[] {"offers: " + w};
        Map<String, Object> os = IntentJs.obj(o);
        String ref;
        try { ref = offerSetRef(os); } catch (RuntimeException e) { return new Object[] {"offers: the offer set is not strictly canonical"}; }
        if (!ref.equals(committed)) return new Object[] {"offers: the supplied offer set does not match the committed reference"};
        String se = IntentArtifacts.artifactSuiteError(os);
        if (se != null) return new Object[] {"offers: signature suite: " + se};
        Map<String, Object> key = null;
        for (Object k : (List<?>) policy.get("site_keys")) if (os.get("kid").equals(IntentJs.get(k, "kid"))) { key = IntentJs.obj(k); break; }
        if (key == null) return new Object[] {"offers: signing key '" + os.get("kid") + "' is not pinned"};
        if (!IntentArtifacts.verifyArtifactSig(OFFER_SET_DOMAIN, os, key.get("pk"), key.get("pq_pk"))) return new Object[] {"offers: bad site signature"};
        if (!os.get("site").equals(aud)) return new Object[] {"offers: the offer set was issued for another audience"};
        if (!os.get("session").equals(session)) return new Object[] {"offers: the offer set is bound to another session"};
        if (!clock) return new Object[] {"offers: no usable clock (now must be a safe integer): the offer set counts as stale"};
        double issued = IntentJs.num(os.get("issued_at"));
        if (issued > now + skewMs) return new Object[] {"offers: the offer set is issued in the future"};
        if (now - issued > IntentJs.num(policy.get("max_age_ms"))) return new Object[] {"offers: the offer set is stale"};
        if (!Boolean.TRUE.equals(os.get("complete"))) return new Object[] {"offers: the offer set is not declared complete"};
        Map<?, ?> filter = (Map<?, ?>) policy.get("filter");
        if (!queryCovers((Map<?, ?>) os.get("query"), (Map<?, ?>) filter.get("query"))) return new Object[] {"offers: the search was narrowed beyond the intent filter (coverage)"};
        Predicates.Resolved id = IntentArtifacts.resolveParamPath(params, policy.get("offer_param"));
        if (!id.found || !(id.value instanceof String)) return new Object[] {"offers: the action names no offer id at the declared parameter"};
        Map<?, ?> chosen = null;
        for (Object x : (List<?>) os.get("offers")) if (id.value.equals(((Map<?, ?>) x).get("offer_id"))) { chosen = (Map<?, ?>) x; break; }
        if (chosen == null) return new Object[] {"offers: the chosen offer is not in the signed offer set"};
        if (!offerMatches(chosen, (Map<?, ?>) filter.get("offer"))) return new Object[] {"offers: the chosen offer does not satisfy the intent filter"};
        long price = IntentJs.lng(chosen.get("price"));
        long min = price;
        for (Object x : (List<?>) os.get("offers")) {
            long px = IntentJs.lng(((Map<?, ?>) x).get("price"));
            if (offerMatches((Map<?, ?>) x, (Map<?, ?>) filter.get("offer")) && px < min) min = px;
        }
        return new Object[] {null, price - min};
    }
}
