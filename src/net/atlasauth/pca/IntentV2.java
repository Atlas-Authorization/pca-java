package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The Intent Layer v2 checks of the core verifier (packages/pca/src/intent-v2.ts {@code decideIntentV2}), in their
 * normative order after {@code intent} (rule 12):
 * {@code schema} (rule 14) -&gt; {@code intent_session} (rule 13) -&gt; {@code layers} (V5) -&gt; {@code accumulators} (rule 15)
 * -&gt; {@code facts} / {@code provenance} / {@code classes} (rules 16-18, {@link IntentWB}).
 *
 * <p>REPORTING: {@code schema} iff the PCActn carries {@code intent_session} or the policy sets
 * {@code schema.closed_world: true}; {@code intent_session} iff the PCActn carries it or {@code session.require} is true;
 * {@code layers} iff the PCActn carries {@code intent_session} and the verifier configured {@code layers};
 * {@code accumulators} iff the PCActn carries {@code intent_session}; the W-B checks iff the PCActn carries
 * {@code intent_session} and {@link IntentWB} reports them. Checks 1-4 are independent; the W-B checks are one unit. A
 * rule-17 {@code question} fails {@code provenance} with reason {@code intent_required: ...}. Within a check the FIRST
 * failing step wins. Never throws.
 */
public final class IntentV2 {
    private IntentV2() {}

    /**
     * The verifier state the v2 checks read (verifier-held, never the agent's): {@code {policy?, params?, schema?: {docs,
     * keys}, session?: {root?, grants?, revocation?}, layers?, wb?: {artifacts?, policy?}, acc?: {state?, monitors?,
     * receipts?, last_seq?, sequencer_keys?}}} as a JSON tree (the {@code context.intent_v2} object of the vectors).
     */
    public static final class Context {
        final Map<String, Object> raw;
        /** False for a PRESENT context that is not a JSON object (null included): every reportable v2 check fails. */
        final boolean wellFormed;
        private Context(Map<String, Object> raw, boolean wellFormed) { this.raw = raw; this.wellFormed = wellFormed; }

        /**
         * From the parsed JSON value of a PRESENT {@code intent_v2} member (normalized to binary64 number semantics). A
         * non-object (JSON null included) is a malformed context, never "no context": pass null only when the member is absent.
         */
        public static Context fromJson(Object o) {
            Object n = IntentJs.normalize(o);
            return n instanceof Map ? new Context(IntentJs.obj(n), true) : new Context(new LinkedHashMap<>(), false);
        }

        /** From raw JSON text (lenient parse); null when it is not an object. */
        public static Context fromJsonText(String text) { return fromJson(Json.parseLenient(text)); }

        /** A copy with {@code params} replaced (a host supplying the plaintext params it parsed from the request). */
        public Context withParams(Object params) {
            Map<String, Object> m = new LinkedHashMap<>(raw);
            m.put("params", IntentJs.normalize(params));
            return new Context(m, wellFormed);
        }

        Object get(String... path) {
            Object cur = raw;
            for (String k : path) cur = IntentJs.get(cur, k);
            return cur;
        }
        boolean has(String... path) {
            Object cur = raw;
            for (int i = 0; i < path.length - 1; i++) cur = IntentJs.get(cur, path[i]);
            return IntentJs.own(cur, path[path.length - 1]);
        }
    }

    /** One reported v2 check. */
    public static final class Check {
        public final String name;
        public final boolean ok;
        public final String reason;
        Check(String name, boolean ok, String reason) { this.name = name; this.ok = ok; this.reason = reason; }
    }

    /** The checks in reporting order and the verifier-computed predicate env ({@code canon}, {@code acc}, {@code mon}, {@code world}, {@code prov}, {@code class}). */
    public static final class Decision {
        public final List<Check> checks = new ArrayList<>();
        public final Map<String, Object> env = new LinkedHashMap<>();
    }

    /** True iff any v2 check would be reported. */
    public static boolean active(Map<String, Object> p, Context ctx) {
        return p.containsKey("intent_session") || closedWorld(ctx) || sessionRequired(ctx) || mapRequired(ctx);
    }
    private static boolean mapRequired(Context ctx) { return ctx != null && Boolean.TRUE.equals(ctx.get("policy", "map", "require")); }
    /** The PCActn's {@code intent_session.map_form} is {@code "commit"} (rule 19). */
    private static boolean mapCommitted(Map<String, Object> p) { return IntentMap.MAP_FORM_COMMIT.equals(IntentJs.get(p.get("intent_session"), "map_form")); }
    private static boolean closedWorld(Context ctx) { return ctx != null && Boolean.TRUE.equals(ctx.get("policy", "schema", "closed_world")); }
    private static boolean sessionRequired(Context ctx) { return ctx != null && Boolean.TRUE.equals(ctx.get("policy", "session", "require")); }

    private static boolean isMap(Object o) { return o instanceof Map; }
    private static boolean optMap(Object o, String k) { return !IntentJs.own(o, k) || isMap(IntentJs.get(o, k)); }
    private static boolean optList(Object o, String k) { return !IntentJs.own(o, k) || IntentJs.get(o, k) instanceof List; }

    /**
     * The verifier context is closed and typed at the top level (README "absent vs null" and "the v2 policy is closed and
     * typed"): a malformed member fails every reportable v2 check. Null = well-formed.
     */
    static String contextError(Context ctx) {
        if (ctx == null) return null;
        if (!ctx.wellFormed) return "the v2 verifier context must be an object";
        Map<String, Object> c = ctx.raw;
        if (!optMap(c, "policy")) return "policy must be an object";
        if (c.containsKey("policy")) {
            Map<String, Object> pr = IntentJs.obj(c.get("policy"));
            for (String k : pr.keySet()) if (!k.equals("session") && !k.equals("schema") && !k.equals("acc") && !k.equals("map")) return "policy: unknown member '" + k + "'";
            if (!optMap(pr, "session")) return "policy.session must be an object";
            if (pr.containsKey("session")) {
                Map<String, Object> o = IntentJs.obj(pr.get("session"));
                for (String k : o.keySet()) if (!k.equals("require") && !k.equals("max_revocation_age_s")) return "policy.session: unknown member '" + k + "'";
                if (o.containsKey("require") && !(o.get("require") instanceof Boolean)) return "policy.session.require must be a boolean";
                if (o.containsKey("max_revocation_age_s") && !IntentJs.isNonNeg(o.get("max_revocation_age_s"))) return "policy.session.max_revocation_age_s must be a non-negative safe integer";
            }
            if (!optMap(pr, "schema")) return "policy.schema must be an object";
            if (pr.containsKey("schema")) {
                Map<String, Object> o = IntentJs.obj(pr.get("schema"));
                for (String k : o.keySet()) if (!k.equals("closed_world")) return "policy.schema: unknown member '" + k + "'";
                if (o.containsKey("closed_world") && !(o.get("closed_world") instanceof Boolean)) return "policy.schema.closed_world must be a boolean";
            }
            if (!optMap(pr, "acc")) return "policy.acc must be an object";
            if (pr.containsKey("acc")) {
                Map<String, Object> o = IntentJs.obj(pr.get("acc"));
                for (String k : o.keySet()) if (!k.equals("max_receipt_age_s") && !k.equals("max_keyset_age_s")) return "policy.acc: unknown member '" + k + "'";
                for (String k : new String[] {"max_receipt_age_s", "max_keyset_age_s"})
                    if (o.containsKey(k) && !IntentJs.isNonNeg(o.get(k))) return "policy.acc." + k + " must be a non-negative safe integer";
            }
            if (!optMap(pr, "map")) return "policy.map must be an object";
            if (pr.containsKey("map")) {
                Map<String, Object> o = IntentJs.obj(pr.get("map"));
                for (String k : o.keySet()) if (!k.equals("require") && !k.equals("max_residual_risk_ppm")) return "policy.map: unknown member '" + k + "'";
                if (o.containsKey("require") && !(o.get("require") instanceof Boolean)) return "policy.map.require must be a boolean";
                if (o.containsKey("max_residual_risk_ppm") && !IntentJs.isNonNeg(o.get("max_residual_risk_ppm"))) return "policy.map.max_residual_risk_ppm must be a non-negative safe integer";
            }
        }
        if (!optMap(c, "params")) return "params must be an object";
        for (String k : new String[] {"schema", "session", "acc"}) if (!optMap(c, k)) return k + " must be an object";
        if (!optMap(c, "map")) return "map must be an object";
        if (c.containsKey("map")) for (String k : IntentJs.obj(c.get("map")).keySet()) if (!k.equals("disclosure")) return "map: unknown member '" + k + "'";
        if (c.containsKey("layers")) {
            if (!isMap(c.get("layers"))) return "layers must be an object";
            for (Map.Entry<String, Object> e : IntentJs.obj(c.get("layers")).entrySet()) {
                if (!List.of("org", "site", "std").contains(e.getKey())) return "layers: unknown member '" + e.getKey() + "'";
                if (!isMap(e.getValue()) || !(IntentJs.get(e.getValue(), "predicates") instanceof List)) return "layers." + e.getKey() + " must be {predicates: [...]}";
            }
        }
        if (c.containsKey("wb")) {
            Object wb = c.get("wb");
            if (!isMap(wb)) return "wb must be an object";
            if (!optMap(wb, "artifacts")) return "wb.artifacts must be an object";
            if (IntentJs.own(wb, "artifacts")) {
                Object a = IntentJs.get(wb, "artifacts");
                for (String k : new String[] {"facts", "labels", "verdicts"}) if (!optList(a, k)) return "wb.artifacts." + k + " must be an array";
                if (!optMap(a, "offer_set")) return "wb.artifacts.offer_set must be an object";
            }
            if (!optMap(wb, "policy")) return "wb.policy must be an object";
            if (IntentJs.own(wb, "policy")) {
                Object p = IntentJs.get(wb, "policy");
                if (!optMap(p, "world") || !optMap(p, "provenance")) return "wb.policy.world / provenance must be objects";
                if (!optList(p, "classifiers")) return "wb.policy.classifiers must be an array";
            }
        }
        return null;
    }

    private static String schemaCtxError(Context ctx) {
        if (ctx == null || !ctx.has("schema")) return null;
        Object sc = ctx.get("schema");
        if (!isMap(sc) || !(IntentJs.get(sc, "docs") instanceof List) || !(IntentJs.get(sc, "keys") instanceof List)) return "the schema context must be {docs: [...], keys: [...]}";
        return null;
    }

    private static String sessionCtxError(Context ctx) {
        if (ctx == null || !ctx.has("session")) return null;
        Object se = ctx.get("session");
        if (!isMap(se)) return "the session context must be an object";
        if (!optList(se, "grants")) return "the session grants must be an array";
        if (!optMap(se, "revocation")) return "the session revocation evidence must be an object";
        if (!optMap(se, "revocation_last")) return "the tracked last revocation epoch must be an object";
        if (IntentJs.own(se, "pq_pins")) {
            Object pp = IntentJs.get(se, "pq_pins");
            if (!isMap(pp)) return "the session pq_pins must be an object of strings";
            for (Object x : ((Map<?, ?>) pp).values()) if (!(x instanceof String)) return "the session pq_pins must be an object of strings";
        }
        return null;
    }

    private static String accCtxError(Context ctx) {
        if (ctx == null || !ctx.has("acc")) return null;
        Object a = ctx.get("acc");
        if (!isMap(a)) return "the accumulator context must be an object";
        for (String k : new String[] {"state", "monitors", "last_seq", "keyset_versions"}) if (!optMap(a, k)) return "acc." + k + " must be an object";
        if (IntentJs.own(a, "keyset_versions")) for (Object v : IntentJs.obj(IntentJs.get(a, "keyset_versions")).values()) {
            String e = IntentAcc.trackedKeySetError(v);
            if (e != null) return "acc.keyset_versions: " + e;
        }
        for (String k : new String[] {"receipts", "sequencer_keys"}) if (!optList(a, k)) return "acc." + k + " must be an array";
        if (IntentJs.own(a, "last_seq")) for (Object v : IntentJs.obj(IntentJs.get(a, "last_seq")).values()) if (!IntentJs.isNonNeg(v)) return "acc.last_seq values must be non-negative safe integers";
        return null;
    }

    /** A failing step's reason, or null on pass. */
    private interface Step { String run(); }

    private static Object cget(Context ctx, String... path) { return ctx == null ? null : ctx.get(path); }

    // ---- rule 14 ----
    private static String schemaStep(Map<String, Object> p, Context ctx, Object[] matched) {
        String ce = schemaCtxError(ctx);
        if (ce != null) return ce;
        Object docs = cget(ctx, "schema", "docs");
        if (!(docs instanceof List) || ((List<?>) docs).isEmpty()) return "this verifier has no action schema configured";
        Object doc = null;
        if (p.containsKey("intent_session")) {
            Object want = IntentJs.get(p.get("intent_session"), "schema");
            for (Object d : (List<?>) docs) {
                boolean hit;
                try { hit = ActionSchema.digest(d).equals(want); } catch (RuntimeException e) { hit = false; }
                if (hit) { doc = d; break; }
            }
            if (doc == null) return "intent_session.schema names no schema this verifier accepts";
        } else doc = ((List<?>) docs).get(0);
        String v = ActionSchema.verify(doc, ctx.get("schema", "keys"));
        if (v != null) return "schema does not verify: " + v;
        if (!IntentJs.get(doc, "aud").equals(p.get("aud"))) return "schema aud does not match the PCActn aud";
        Object params = cget(ctx, "params");
        if (!(params instanceof Map)) return "no plaintext params to check against the schema (closed world needs them)";
        if (!Pca.paramsDigest(params).equals(IntentJs.get(p.get("action"), "params_digest"))) return "params do not hash to action.params_digest";
        ActionSchema.Conform c = ActionSchema.conform(doc, verbOf(p), params);
        if (!c.ok) return "schema_violation: " + c.code + ": " + c.reason;
        matched[0] = doc;
        return null;
    }

    private static String verbOf(Map<String, Object> p) { return IntentRevocation.jsText(IntentJs.get(p.get("action"), "verb"), IntentJs.own(p.get("action"), "verb")); }
    private static String resourceOf(Map<String, Object> p) { return IntentRevocation.jsText(IntentJs.get(p.get("action"), "resource"), IntentJs.own(p.get("action"), "resource")); }

    // ---- the bound root (rules 13 and 15) ----
    private static String boundRoot(Map<String, Object> is, Context ctx, double now, Object[] out) {
        if (ctx == null || !ctx.has("session", "root")) return "no session root for this session";
        Object S = ctx.get("session", "root");
        // a PQ / hybrid root verifies only under the VERIFIER's pin for its signer (session.pq_pins), never its own principals
        String v = IntentSession.verifyRoot(S, ctx.has("session", "pq_pins") ? ctx.get("session", "pq_pins") : null);
        if (v != null) return "session root: " + v;
        if (!IntentSession.rootDigest(S).equals(is.get("root"))) return "intent_session.root is not the digest of the session root";
        if (!IntentJs.get(S, "session").equals(is.get("session"))) return "the session root names another session";
        if (!(now < IntentJs.num(IntentJs.get(S, "expires_at")))) return "the session root has expired";
        out[0] = S;
        return null;
    }

    // ---- rule 13 ----
    private static String sessionStep(Map<String, Object> p, Map<String, Object> grant, Context ctx, double now) {
        boolean maxAgeSet = ctx != null && ctx.has("policy", "session", "max_revocation_age_s");
        Object maxAgeS = cget(ctx, "policy", "session", "max_revocation_age_s");
        if (maxAgeSet && !IntentJs.isNonNeg(maxAgeS)) return "session policy misconfigured: max_revocation_age_s must be a non-negative safe integer (fail closed)";
        if (!p.containsKey("intent_session")) return "this verifier requires an intent_session but the PCActn carries none";
        String ce = sessionCtxError(ctx);
        if (ce != null) return ce;
        Map<String, Object> is = IntentJs.obj(p.get("intent_session"));
        if (!p.containsKey("intent")) return "an intent_session needs the envelope.intent binding";
        Map<String, Object> intent = IntentJs.obj(p.get("intent"));
        Object[] r = new Object[1];
        String e = boundRoot(is, ctx, now, r);
        if (e != null) return e;
        Map<String, Object> S = IntentJs.obj(r[0]);
        if (!S.get("intent_ref").equals(intent.get("ref"))) return "intent.ref is not the session statement";
        if (!IntentJs.get(S.get("schema"), "digest").equals(is.get("schema"))) return "intent_session.schema is not the session schema";
        if (!IntentJs.get(S.get("schema"), "aud").equals(p.get("aud"))) return "the session schema is for another audience";
        long seq = IntentJs.lng(is.get("seq"));
        if (seq == 0 && !intent.get("map_digest").equals(IntentJs.get(IntentJs.get(S.get("layers"), "task"), "map_digest"))) return "a seq-0 action must use the session task map";
        Map<String, Object> gc = IntentSession.grantSessionCaveat(grant);
        String ge = IntentSession.caveatError(gc);
        if (ge != null) return "admitting root: " + ge;
        if (!gc.get("session").equals(is.get("session")) || !gc.get("root").equals(is.get("root")) || IntentJs.lng(gc.get("seq")) != seq)
            return "the admitting root is bound to another session, root or seq";
        Set<String> principals = new LinkedHashSet<>();
        for (Object x : (List<?>) S.get("principals")) principals.add((String) IntentJs.get(x, "key"));
        if (!principals.contains(IntentJs.get(grant, "issuer"))) return "the admitting root is not signed by a session principal";
        Object priorO = ctx.has("session", "grants") ? ctx.get("session", "grants") : List.of();
        if (((List<?>) priorO).size() < seq) return "the verifier does not hold the " + seq + " earlier grants of this session";
        List<?> prior = (List<?>) priorO;
        for (int i = 0; i < seq; i++) {
            Object g = prior.get(i);
            if (!isMap(g) || !(IntentJs.get(g, "id") instanceof String) || !(IntentJs.get(g, "issuer") instanceof String)) return "session grant " + i + " is not a capability";
            String gse = IntentJs.suiteError(IntentJs.get(g, "alg"), IntentJs.own(g, "alg"));
            if (gse != null) return "session grant " + i + ": " + gse;
            Map<String, Object> c = IntentSession.grantSessionCaveat(g);
            if (IntentSession.caveatError(c) != null || !c.get("session").equals(is.get("session")) || !c.get("root").equals(is.get("root")) || IntentJs.lng(c.get("seq")) != i)
                return "session grant " + i + " does not belong to this session at seq " + i;
            if (!principals.contains(IntentJs.get(g, "issuer"))) return "session grant " + i + " is not signed by a session principal";
            if (i > 0 && !IntentJs.jsonEquals(c.get("prev"), IntentJs.get(prior.get(i - 1), "id"))) return "session grant " + i + " does not chain to grant " + (i - 1);
        }
        if (seq > 0 && !IntentJs.jsonEquals(gc.get("prev"), IntentJs.get(prior.get((int) seq - 1), "id"))) return "the admitting root does not chain to grant " + (seq - 1);
        boolean sRev = S.containsKey("revocation");
        if (sRev || maxAgeSet) {
            double ages = Double.POSITIVE_INFINITY;
            if (sRev) ages = Math.min(ages, IntentJs.num(IntentJs.get(S.get("revocation"), "max_age_s")));
            if (maxAgeSet) ages = Math.min(ages, IntentJs.num(maxAgeS));
            double maxAgeMs = ages * 1000;
            if (!sRev) return "revocation: the policy requires a revocation epoch but the session root names no revocation authority";
            Object authority = IntentJs.get(S.get("revocation"), "key");
            List<String> ids = new ArrayList<>();
            ids.add(IntentRevocation.sessionRevocationId((String) is.get("session")));
            ids.add(IntentRevocation.mapRevocationId((String) intent.get("map_digest")));
            for (int i = 0; i < seq; i++) ids.add(IntentRevocation.deltaRevocationId(IntentRevocation.jsText(IntentJs.get(prior.get(i), "id"), IntentJs.own(prior.get(i), "id"))));
            ids.add(IntentRevocation.deltaRevocationId(IntentRevocation.jsText(grant.get("id"), grant.containsKey("id"))));
            Object std = IntentJs.get(S.get("layers"), "std");
            if (IntentRevocation.truthy(std))
                ids.add(IntentRevocation.profileRevocationId((String) IntentJs.get(std, "profile"), IntentRevocation.jsText(IntentJs.get(std, "version"), true)));
            // only the dedicated authority S.revocation.key signs epochs; a PQ epoch verifies only under S.revocation.pq_pk
            Map<String, Object> pqPins = new LinkedHashMap<>();
            if (IntentJs.own(S.get("revocation"), "pq_pk")) pqPins.put((String) authority, IntentJs.get(S.get("revocation"), "pq_pk"));
            boolean lastPresent = ctx != null && ctx.has("session", "revocation_last");
            String rv = IntentRevocation.checkSessionRevocation(cget(ctx, "session", "revocation"), (String) is.get("session"), authority, ids, now, maxAgeMs, null, pqPins,
                lastPresent, lastPresent ? ctx.get("session", "revocation_last") : null);
            if (rv != null) return "revocation: " + rv;
        }
        return null;
    }

    // ---- rule 15 ----
    private static String accStep(Map<String, Object> p, Context ctx, double now, Map<String, Object> accEnv, Map<String, Object> monEnv) {
        Map<String, Object> is = IntentJs.obj(p.get("intent_session"));
        Object[] r = new Object[1];
        String e = boundRoot(is, ctx, now, r);
        if (e != null) return e;
        Map<String, Object> S = IntentJs.obj(r[0]);
        String ce = accCtxError(ctx);
        if (ce == null) ce = schemaCtxError(ctx);
        if (ce != null) return ce;
        String verb = verbOf(p);
        List<?> claims = is.get("acc") instanceof List ? (List<?>) is.get("acc") : List.of();
        List<?> accs = (List<?>) S.get("accumulators");
        for (Object c : claims) {
            Map<String, Object> a = findById(accs, IntentJs.get(c, "id"));
            if (a == null) return "claim '" + IntentJs.get(c, "id") + "' names no accumulator of the session";
            if ("wallet".equals(IntentJs.get(a.get("holder"), "kind"))) return "accumulator '" + IntentJs.get(c, "id") + "' is wallet-held and cannot be claimed at a site";
        }
        Object docs = cget(ctx, "schema", "docs");
        Object schemaDoc = null;
        if (docs instanceof List) {
            for (Object d : (List<?>) docs) {
                boolean hit;
                try { hit = ActionSchema.digest(d).equals(is.get("schema")); } catch (RuntimeException x) { hit = false; }
                if (hit) { schemaDoc = d; break; }
            }
        }
        Object params = cget(ctx, "params");
        Object state = ctx.has("acc", "state") ? ctx.get("acc", "state") : Map.of();
        for (Object aO : accs) {
            Map<String, Object> a = IntentJs.obj(aO);
            String id = (String) a.get("id");
            Map<String, Object> holder = IntentJs.obj(a.get("holder"));
            Object hk = holder.get("kind");
            if ("wallet".equals(hk)) continue;
            Map<String, Object> sel = IntentJs.obj(a.get("sel"));
            if (sel.containsKey("accumulates_into") && schemaDoc == null) return "accumulator '" + id + "' selects by accumulates_into but the session schema is not available";
            boolean selected = IntentAcc.accSelects(a, verb, schemaDoc);
            Map<String, Object> claim = findById(claims, id);
            boolean hasPre = IntentJs.own(state, id);
            Object pre = hasPre ? IntentJs.get(state, id) : null;
            if (!selected) {
                if (claim != null) return "claim '" + id + "' for an accumulator this action does not feed";
                if ("site_local".equals(hk) && hasPre) {
                    String pe = IntentAcc.preStateError(a.get("agg"), pre);
                    if (pe != null) return "accumulator '" + id + "': " + pe;
                    accEnv.put(id, postOf(IntentAcc.preValue(a.get("agg"), (Map<?, ?>) pre)));
                }
                continue;
            }
            if (claim == null) return "no claim for accumulator '" + id + "' that this action feeds";
            if (!(params instanceof Map)) return "no plaintext params to compute accumulator values";
            Map<String, Object> pm = IntentJs.obj(params);
            if (a.get("key") != null) {
                String key = (String) a.get("key");
                String name = key.substring("action.params.".length());
                if (!pm.containsKey(name)) return "accumulator '" + id + "': the key parameter " + key + " is missing";
                Map<String, Object> verbDecl = schemaDoc != null ? ActionSchema.schemaVerb(schemaDoc, verb) : null;
                Object kd = verbDecl == null ? null : IntentJs.get(verbDecl.get("params"), key);
                if (kd == null || ((String) IntentJs.get(kd, "semantic")).startsWith("text."))
                    return "accumulator '" + id + "': the key must be a schema-declared identity (not free text)";
            }
            IntentAcc.AccValue v = IntentAcc.accValueOf(a, verb, pm, schemaDoc);
            if (v.reason != null) return "accumulator '" + id + "': " + v.reason;
            long post;
            if ("site_local".equals(hk)) {
                if (claim.containsKey("receipt")) return "accumulator '" + id + "' is site-local: a receipt is not accepted";
                if (!hasPre) return "no state for site-local accumulator '" + id + "'";
                String pe = IntentAcc.preStateError(a.get("agg"), pre);
                if (pe != null) return "accumulator '" + id + "': " + pe;
                Long x = IntentAcc.combineAcc(a.get("agg"), (Map<?, ?>) pre, v);
                if (x == null) return "accumulator '" + id + "' overflows 2^53-1";
                post = x;
            } else {
                if (!claim.containsKey("receipt")) return "accumulator '" + id + "' is sequenced: the claim needs a reservation receipt";
                Object rcs = ctx.has("acc", "receipts") ? ctx.get("acc", "receipts") : List.of();
                Map<String, Object> rc = null;
                for (Object x : IntentArtifacts.iterable(rcs)) {
                    boolean hit;
                    try { hit = IntentAcc.receiptDigest(x).equals(claim.get("receipt")); } catch (RuntimeException ex) { hit = false; }
                    if (hit) { rc = x instanceof Map ? IntentJs.obj(x) : null; if (rc != null) break; }
                }
                if (rc == null) return "the reservation receipt for '" + id + "' was not presented";
                Object keySets = ctx.has("acc", "sequencer_keys") ? ctx.get("acc", "sequencer_keys") : List.of();
                Object pa = ctx.get("policy", "acc");
                Object root = holder.get("root");
                double maxReceiptAgeMs = IntentJs.own(pa, "max_receipt_age_s") ? IntentJs.num(IntentJs.get(pa, "max_receipt_age_s")) * 1000 : IntentAcc.DEFAULT_MAX_RECEIPT_AGE_MS;
                double maxKeySetAgeMs = IntentJs.own(pa, "max_keyset_age_s") ? IntentJs.num(IntentJs.get(pa, "max_keyset_age_s")) * 1000 : IntentAcc.DEFAULT_MAX_KEYSET_AGE_MS;
                Object kv = ctx.get("acc", "keyset_versions");
                Object tracked = root instanceof String && IntentJs.own(kv, (String) root) ? IntentJs.get(kv, (String) root) : null;
                if (!IntentAcc.verifyReceiptAgainstHolder(rc, holder, keySets, now, maxReceiptAgeMs, maxKeySetAgeMs, tracked)) {
                    String rse = IntentJs.suiteError(rc.get("alg"), rc.containsKey("alg"));
                    if (rse != null && rse.startsWith(IntentJs.UNSUPPORTED_SUITE)) return "the reservation receipt for '" + id + "': " + IntentJs.UNSUPPORTED_SUITE;
                    return "the reservation receipt for '" + id + "' is not signed by a key the session sequencer's root-signed key set lists for its issue time";
                }
                if (!rc.get("session").equals(is.get("session")) || !rc.get("acc").equals(id) || !rc.get("aud").equals(p.get("aud")))
                    return "the reservation receipt for '" + id + "' is for another session, accumulator or audience";
                if (!rc.get("pcactn_digest").equals(IntentAcc.pcactnReservationDigest(p))) return "the reservation receipt for '" + id + "' is for another action";
                if (!(now <= IntentJs.num(rc.get("expires_at")))) return "the reservation receipt for '" + id + "' has expired";
                Object lastSeq = ctx.has("acc", "last_seq") ? ctx.get("acc", "last_seq") : Map.of();
                if (IntentJs.own(lastSeq, id)) {
                    Object last = IntentJs.get(lastSeq, id);
                    if (!(IntentJs.num(rc.get("seq")) > IntentJs.num(last)))
                        return "the reservation receipt for '" + id + "' replays seq " + IntentJs.lng(rc.get("seq")) + " (last accepted " + IntentJs.lng(last) + ")";
                }
                if (!IntentAcc.receiptArithmeticOk(a.get("agg"), rc, v.val)) return "the reservation receipt for '" + id + "' does not add up";
                post = IntentJs.lng(rc.get("post"));
            }
            if (a.containsKey("domain_max") && post > IntentJs.lng(a.get("domain_max"))) return "accumulator '" + id + "' post " + post + " is outside its domain (max " + IntentJs.lng(a.get("domain_max")) + ")";
            if (IntentJs.lng(claim.get("post")) != post) return "claimed post " + IntentJs.lng(claim.get("post")) + " for '" + id + "' differs from the verifier's " + post;
            accEnv.put(id, postOf(post));
        }
        Object mons = ctx.has("acc", "monitors") ? ctx.get("acc", "monitors") : Map.of();
        for (Object mO : (List<?>) S.get("monitors")) {
            Map<String, Object> m = IntentJs.obj(mO);
            String id = (String) m.get("id");
            Object st = IntentJs.own(mons, id) ? IntentJs.get(mons, id) : null;
            if (!(st instanceof String) || !IntentAcc.monitorStates(m).contains(st)) return "no valid state for monitor '" + id + "'";
            Map<String, Object> s = new LinkedHashMap<>();
            s.put("state", st);
            monEnv.put(id, s);
        }
        return null;
    }

    private static Map<String, Object> postOf(long post) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("post", IntentJs.ofLong(post));
        return m;
    }

    private static Map<String, Object> findById(List<?> xs, Object id) {
        for (Object x : xs) if (x instanceof Map && id != null && id.equals(((Map<?, ?>) x).get("id"))) return IntentJs.obj(x);
        return null;
    }

    private static void run(Decision out, String name, boolean clockOk, Step f) {
        String why;
        try {
            why = clockOk ? f.run() : "the verifier clock is not a safe integer (fail closed)";
        } catch (RuntimeException | StackOverflowError e) {
            why = name + " error (fail closed): " + e.getClass().getSimpleName();
        }
        out.checks.add(new Check(name, why == null, why));
    }

    /**
     * Run the v2 checks for a wire-valid PCActn {@code p} under the verifier's root {@code grant} (never throws: an
     * internal error fails the check being evaluated).
     */
    public static Decision decide(Map<String, Object> p, Map<String, Object> grant, Context ctx, long nowL) {
        Decision out = new Decision();
        double now = nowL;
        boolean present = p.containsKey("intent_session");
        boolean clockOk = Math.abs(nowL) <= 9007199254740991L;
        String ctxErr = contextError(ctx);
        if (ctxErr != null) {
            // a malformed verifier context fails closed: every v2 check that could be reported fails with the reason
            out.checks.add(new Check("schema", false, "malformed v2 context: " + ctxErr));
            out.checks.add(new Check("intent_session", false, "malformed v2 context: " + ctxErr));
            if (present) out.checks.add(new Check("accumulators", false, "malformed v2 context: " + ctxErr));
            if (present && mapCommitted(p)) out.checks.add(new Check("map", false, "malformed v2 context: " + ctxErr));
            return out;
        }
        if (present || closedWorld(ctx)) {
            run(out, "schema", clockOk, () -> {
                Object[] matched = new Object[1];
                String why = schemaStep(p, ctx, matched);
                if (why == null) out.env.put("canon", ActionSchema.canonProjection(matched[0], verbOf(p), IntentJs.obj(ctx.get("params"))));
                return why;
            });
        }
        if (present || sessionRequired(ctx)) run(out, "intent_session", clockOk, () -> sessionStep(p, grant, ctx, now));
        boolean mapActive = mapCommitted(p) || mapRequired(ctx);
        Object params = cget(ctx, "params");
        Map<String, Object> action = new LinkedHashMap<>();
        action.put("verb", verbOf(p));
        action.put("resource", resourceOf(p));
        action.put("params", params instanceof Map ? params : new LinkedHashMap<String, Object>());
        if (present && ctx != null && ctx.has("layers")) {
            run(out, "layers", clockOk, () -> {
                Map<String, Object> env = new LinkedHashMap<>();
                if (out.env.containsKey("canon")) env.put("canon", out.env.get("canon"));
                Map<String, Object> actx = new LinkedHashMap<>();
                actx.put("action", action);
                actx.put("env", env);
                Object layers = ctx.get("layers");
                for (String k : new String[] {"org", "site", "std"}) {
                    if (!IntentJs.own(layers, k)) continue;
                    Object layer = IntentJs.get(layers, k);
                    if (IntentJs.obj(layer).size() != 1) return "layers: the " + k + " ceiling is malformed (null or not {predicates: [...]})";
                    if (!Predicates.evaluatePredicates(IntentJs.get(IntentJs.get(layers, k), "predicates"), actx))
                        return "layers: the action is outside the " + k + " ceiling (a ceiling is never a question)";
                }
                return null;
            });
        }
        if (present) {
            run(out, "accumulators", clockOk, () -> {
                Map<String, Object> acc = new LinkedHashMap<>(), mon = new LinkedHashMap<>();
                String why = accStep(p, ctx, now, acc, mon);
                if (why == null) { out.env.put("acc", acc); out.env.put("mon", mon); }
                return why;
            });
            if (mapActive) run(out, "map", clockOk, () -> mapStep(p, ctx));
            IntentWB.Result wb = null;
            try {
                Map<String, Object> in = new LinkedHashMap<>();
                in.put("now", IntentJs.ofLong(nowL));
                in.put("aud", IntentRevocation.jsText(p.get("aud"), p.containsKey("aud")));
                in.put("session", IntentJs.get(p.get("intent_session"), "session"));
                in.put("action", action);
                in.put("intent_session", p.get("intent_session"));
                if (ctx != null && ctx.has("wb", "artifacts")) in.put("artifacts", ctx.get("wb", "artifacts"));
                if (ctx != null && ctx.has("wb", "policy")) in.put("policy", ctx.get("wb", "policy"));
                wb = IntentWB.decide(in);
            } catch (RuntimeException e) {
                out.checks.add(new Check("facts", false, "W-B error (fail closed): " + e.getClass().getSimpleName()));
            }
            if (wb != null) {
                for (String name : new String[] {"facts", "provenance", "classes"}) {
                    String c = wb.checks.get(name);
                    if (c == null) continue;
                    if (c.equals("pass")) out.checks.add(new Check(name, true, null));
                    else out.checks.add(new Check(name, false, c.equals("question")
                        ? "intent_required: " + (wb.reason != null ? wb.reason : "a question is required") : (wb.reason != null ? wb.reason : "rejected")));
                }
                if (!wb.outcome.equals("deny")) {
                    if (wb.world != null) out.env.put("world", wb.world);
                    if (wb.prov != null) out.env.put("prov", wb.prov);
                    if (wb.cls != null) out.env.put("class", wb.cls);
                }
            }
        } else if (mapActive) {
            run(out, "map", clockOk, () -> mapStep(p, ctx));
        }
        return out;
    }

    /**
     * Rule 19 ({@code map}, V15 Z0): reported iff the PCActn's {@code intent_session.map_form} is {@code "commit"} or the
     * policy sets {@code map.require: true}; evaluated after {@code accumulators} (independent of the earlier checks) and
     * before W-B.
     */
    private static String mapStep(Map<String, Object> p, Context ctx) {
        if (!mapCommitted(p)) return "this verifier requires a committed map (intent_session.map_form \"commit\")";
        if (!p.containsKey("intent")) return "a committed map needs the envelope.intent binding";
        if (ctx == null || !ctx.has("map", "disclosure")) return "no disclosure of the committed map was presented";
        Object eps = ctx.get("policy", "map", "max_residual_risk_ppm");
        IntentMap.Decision d = IntentMap.decide(IntentJs.get(p.get("intent"), "map_digest"), p.containsKey("action") ? p.get("action") : new LinkedHashMap<String, Object>(),
            ctx.has("params"), ctx.get("params"), ctx.get("map", "disclosure"), ctx.has("policy", "map", "max_residual_risk_ppm") ? IntentJs.num(eps) : null);
        return d.ok ? null : d.reason;
    }
}
