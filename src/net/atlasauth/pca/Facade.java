package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The high-level agent API: compile human-level permissions and limits into a signed grant, then build one proof-carrying action
 * per tool call. Same output as the TypeScript reference's {@code agent()}, byte for byte for fixed keys, salt, session and clock.
 *
 * <pre>{@code
 * Facade.Handle a = Agent.fromPrincipal(new Facade.AgentOptions(principal, "reconcile refunds for October",
 *     Issue.obj("stripe", List.of("refund"), "gmail", List.of("send"))).limits(Issue.obj("refund", "$500/day")).aud("ins_123"));
 * Facade.ActResult r = a.act("stripe.refund", "charge:ch_123", Issue.obj("amount", 42L, "currency", "usd"), null);
 * // send r.headers (PCA-Action and PCA-Provenance) to the resource server; its verifier decides
 * }</pre>
 *
 * <p>Nothing here authorizes anything: every member the facade emits is signed, so a tampered grant or action fails verification
 * downstream. {@link Handle#dryRun} is a local, advisory pre-check only.
 */
public final class Facade {
    private Facade() {}

    // ---- numbers in the reference's JSON form ------------------------------------------------------------------------------

    /** A JSON number for {@code d} as JavaScript writes it: a safe integer as a Long, else the shortest decimal. */
    static Object jn(double d) {
        if (d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0) return (long) d;
        return new Json.Num(Json.fmtNumber(new java.math.BigDecimal(d).toString()));
    }

    /** The text JavaScript prints for a number in a template literal. */
    static String jsText(double d) { return jn(d).toString(); }

    // ---- limit parsing -----------------------------------------------------------------------------------------------------

    /** A parsed limit: {@code amount}, {@code unit} ({@code usd} or {@code count}) and the period window in ms (null when none). */
    public static final class ParsedLimit {
        public final double amount;
        public final String unit;
        public final Long periodMs;
        ParsedLimit(double amount, String unit, Long periodMs) { this.amount = amount; this.unit = unit; this.periodMs = periodMs; }

        /** {@code {amount, unit, periodMs?}}, the reference's member names. */
        public Map<String, Object> toJson() {
            Map<String, Object> m = Issue.obj("amount", jn(amount), "unit", unit);
            if (periodMs != null) m.put("periodMs", periodMs);
            return m;
        }
    }

    /** Longest limit string accepted (the grammar needs about 20 characters). */
    public static final int MAX_LIMIT_LENGTH = 64;

    private static final Map<String, Long> PERIODS = new LinkedHashMap<>();
    static {
        for (String k : new String[] {"s", "sec", "second", "seconds"}) PERIODS.put(k, 1000L);
        for (String k : new String[] {"m", "min", "minute", "minutes"}) PERIODS.put(k, 60_000L);
        for (String k : new String[] {"h", "hr", "hour", "hours"}) PERIODS.put(k, 3_600_000L);
        for (String k : new String[] {"d", "day", "days"}) PERIODS.put(k, 86_400_000L);
        for (String k : new String[] {"w", "week", "weeks"}) PERIODS.put(k, 604_800_000L);
        for (String k : new String[] {"mo", "month", "months"}) PERIODS.put(k, 2_592_000_000L);
    }

    /** JavaScript's white-space class spelled out (Java's Unicode one also matches U+0085, which JavaScript's does not). */
    private static final String JS_WS = "[\\t\\n\\u000B\\f\\r \\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF]";
    private static final Pattern LIMIT_RE = Pattern.compile("^(\\$)?" + JS_WS + "*([0-9]+(?:\\.[0-9]+)?)" + JS_WS + "*(?:/" + JS_WS + "*([a-zA-Z]+))?$");

    /** JavaScript {@code String.prototype.trim}: strips Unicode white space and line terminators from both ends. */
    static String jsTrim(String s) {
        int a = 0, b = s.length();
        while (a < b && jsSpace(s.charAt(a))) a++;
        while (b > a && jsSpace(s.charAt(b - 1))) b--;
        return s.substring(a, b);
    }

    private static boolean jsSpace(char c) { return Character.isWhitespace(c) || Character.isSpaceChar(c) || c == '﻿'; }

    /** Parse {@code "$500/day"}, {@code "$500"}, {@code "10/hour"}, {@code "10"}. Throws on anything malformed or longer than {@link #MAX_LIMIT_LENGTH}. */
    public static ParsedLimit parseLimit(Object sO) {
        if (!(sO instanceof String) || jsTrim((String) sO).isEmpty()) throw new IllegalArgumentException("parseLimit: empty limit");
        String s = (String) sO;
        if (s.length() > MAX_LIMIT_LENGTH) throw new IllegalArgumentException("parseLimit: limit is longer than " + MAX_LIMIT_LENGTH + " characters");
        Matcher m = LIMIT_RE.matcher(jsTrim(s));
        if (!m.matches()) throw new IllegalArgumentException("parseLimit: cannot parse limit '" + s + "'");
        String unit = m.group(1) != null ? "usd" : "count";
        double amount = Double.parseDouble(m.group(2));
        if (Double.isInfinite(amount) || amount < 0) throw new IllegalArgumentException("parseLimit: bad amount in '" + s + "'");
        Long periodMs = null;
        if (m.group(3) != null) {
            periodMs = PERIODS.get(m.group(3).toLowerCase(Locale.ROOT));
            if (periodMs == null) throw new IllegalArgumentException("parseLimit: unknown period '" + m.group(3) + "' in '" + s + "'");
        }
        return new ParsedLimit(amount, unit, periodMs);
    }

    // ---- compiled policy ---------------------------------------------------------------------------------------------------

    /** The policy primitives a grant is minted from. */
    public static final class CompiledPolicy {
        public final List<Object> predicates, caveats;
        public final Map<String, Object> riskPolicy;
        /** The resolved action spec of each granted permission. */
        public final List<Catalog.Spec> actions;
        /** {@code dollars} or {@code risk}. */
        public final String budgetModel;
        /** The parsed limits that matched a granted action, by verb. */
        public final Map<String, ParsedLimit> limits;
        /** The raw limit input as given. */
        public final Map<String, Object> inputLimits;
        /** Limits this offline compiler can only approximate (a {@code $N/period} limit is a per-call ceiling plus a one-period lifetime). */
        public final List<String> approximations;

        CompiledPolicy(List<Object> predicates, List<Object> caveats, Map<String, Object> riskPolicy, List<Catalog.Spec> actions, String budgetModel,
                       Map<String, ParsedLimit> limits, Map<String, Object> inputLimits, List<String> approximations) {
            this.predicates = predicates; this.caveats = caveats; this.riskPolicy = riskPolicy; this.actions = actions; this.budgetModel = budgetModel;
            this.limits = limits; this.inputLimits = inputLimits; this.approximations = approximations;
        }

        /** {@code {predicates, caveats, riskPolicy, budgetModel, limits, approximations}}, the reference's member names. */
        public Map<String, Object> toJson() {
            Map<String, Object> l = new LinkedHashMap<>();
            for (Map.Entry<String, ParsedLimit> e : limits.entrySet()) l.put(e.getKey(), e.getValue().toJson());
            return Issue.obj("predicates", predicates, "caveats", caveats, "riskPolicy", riskPolicy, "budgetModel", budgetModel, "limits", l,
                "approximations", new ArrayList<Object>(approximations));
        }
    }

    /** Conservative fallback for a verb not in the catalog: irreversible, blast radius 0.8; an alias of exactly one action resolves to it. */
    static Catalog.Spec specFor(Catalog catalog, String verb) {
        Catalog.Spec s = catalog.get(verb);
        if (s != null) return s;
        int dot = verb.indexOf('.');
        if (dot > 0) {
            Catalog.Spec a = catalog.resolve(verb.substring(0, dot), verb.substring(dot + 1));
            if (a != null) return a;
        }
        String connector = dot < 0 ? verb : verb.substring(0, dot);
        String action = dot < 0 ? "" : verb.substring(dot + 1);
        return new Catalog.Spec(connector, action.isEmpty() ? verb : action, verb, "irreversible", 0.8, null, "(uncatalogued) " + verb, null, null);
    }

    private static int sev(String cls) { return Caveats.REVERSIBILITY_ORDER.indexOf(cls); }

    /**
     * Compile permissions ({@code {connector: [action, ...]}}) and limits ({@code {action or verb: "$500/day"}}) into predicates,
     * caveats and a risk policy. Pure: no keys, no signing. {@code catalog} (null: {@link Catalog#DEFAULT}), {@code budgetModel}
     * ({@code auto} when null, {@code dollars}, {@code risk}), {@code riskPolicy} (members that override the derived policy; may be
     * null) and {@code now} (ms) are as in the reference.
     */
    public static CompiledPolicy compilePolicy(Map<String, Object> permissions, Map<String, Object> limits, Catalog catalog, String budgetModel,
                                               Map<String, Object> riskPolicy, long now) {
        Catalog cat = catalog != null ? catalog : Catalog.DEFAULT;
        Map<String, Object> raw = limits != null ? limits : new LinkedHashMap<String, Object>();
        List<Catalog.Spec> actions = new ArrayList<>();
        for (Map.Entry<String, Object> e : permissions.entrySet()) {
            if (!(e.getValue() instanceof List)) throw new IllegalArgumentException("compilePolicy: permissions." + e.getKey() + " must be an array");
            for (Object a : (List<?>) e.getValue()) actions.add(specFor(cat, e.getKey() + "." + a));
        }
        if (actions.isEmpty()) throw new IllegalArgumentException("compilePolicy: no permissions granted");

        Map<String, ParsedLimit> parsed = new LinkedHashMap<>();
        List<Object> predicates = new ArrayList<>();
        for (Catalog.Spec s : actions) {
            Object r = raw.get(s.verb);
            if (r == null) r = raw.get(s.action);
            for (String a : s.aliases) if (r == null) r = raw.get(a);
            ParsedLimit lim = null;
            if (r != null) {
                lim = parseLimit(r);
                parsed.put(s.verb, lim);
            }
            List<Object> where = new ArrayList<>();
            if (lim != null && "usd".equals(lim.unit) && s.amountField == null)
                throw new IllegalArgumentException("compilePolicy: '$' limit on '" + s.verb + "' but the catalog gives that verb no amount field, so the limit could not be enforced");
            if (lim != null && "usd".equals(lim.unit)) {
                where.add(Issue.obj("field", "action.params." + s.amountField, "op", "lte", "value", jn(lim.amount)));
                where.add(Issue.obj("field", "action.params." + s.amountField, "op", "gte", "value", 0L));
            }
            Map<String, Object> p = Issue.obj("verb", s.verb, "resource", "*");
            if (!where.isEmpty()) p.put("where", where);
            predicates.add(p);
        }

        List<Object> caveats = new ArrayList<>();
        String strictest = "reversible";
        for (Catalog.Spec s : actions) if (sev(s.reversibility) > sev(strictest)) strictest = s.reversibility;
        caveats.add(Issue.obj("type", "reversibility_max", "class", strictest));
        Long minPeriod = null;
        for (ParsedLimit l : parsed.values()) if (l.periodMs != null && (minPeriod == null || l.periodMs < minPeriod)) minPeriod = l.periodMs;
        if (minPeriod != null) caveats.add(Issue.obj("type", "expires", "at", now + minPeriod));
        // one rate caveat per count limit (caveats are ANDed): a second limit can only narrow
        for (ParsedLimit l : parsed.values())
            if ("count".equals(l.unit) && l.periodMs != null) caveats.add(Issue.obj("type", "rate", "max", jn(l.amount), "per_secs", Math.max(1L, Math.round(l.periodMs / 1000.0))));

        List<ParsedLimit> dollars = new ArrayList<>();
        for (ParsedLimit l : parsed.values()) if ("usd".equals(l.unit)) dollars.add(l);
        String model = "dollars".equals(budgetModel) ? "dollars" : "risk".equals(budgetModel) ? "risk" : dollars.isEmpty() ? "risk" : "dollars";
        boolean hasIrreversible = false;
        for (Catalog.Spec s : actions) if ("irreversible".equals(s.reversibility)) hasIrreversible = true;
        Map<String, Object> rp = Issue.defaultRiskPolicy();
        if ("dollars".equals(model) && !dollars.isEmpty()) {
            double kappa = 0, bMax = 0;
            for (ParsedLimit l : dollars) { kappa = Math.max(kappa, l.amount); bMax += l.amount; }
            Map<String, Object> d = Issue.defaultRiskPolicy();
            // within-cap actions auto-approve only when nothing granted is irreversible
            rp = Issue.obj("weights", Issue.obj("alpha", 0L, "beta", 0L, "gamma", 1L, "delta", 0L, "epsilon", 0L, "zeta", 0L),
                "theta1", hasIrreversible ? d.get("theta1") : 1L, "theta2", hasIrreversible ? d.get("theta2") : 1L,
                "kappa", kappa > 0 ? jn(kappa) : 1L, "lambda", 0L, "rho", d.get("rho"), "bMax", bMax > 0 ? jn(bMax) : 1L);
        }
        if (riskPolicy != null) {
            Map<String, Object> w = new LinkedHashMap<>(Pca.asMap(rp.get("weights")));
            if (riskPolicy.get("weights") instanceof Map) w.putAll(Pca.asMap(riskPolicy.get("weights")));
            Map<String, Object> merged = new LinkedHashMap<>(rp);
            merged.putAll(riskPolicy);
            merged.put("weights", w);
            rp = merged;
        }
        String bad = Authorize.validateRiskPolicy(rp);
        if (bad != null) throw new IllegalArgumentException("compilePolicy: derived risk policy invalid: " + bad);

        List<String> approximations = new ArrayList<>();
        for (Map.Entry<String, ParsedLimit> e : parsed.entrySet())
            if ("usd".equals(e.getValue().unit) && e.getValue().periodMs != null)
                approximations.add(e.getKey() + ": $" + jsText(e.getValue().amount) + "/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap");
        return new CompiledPolicy(predicates, caveats, rp, actions, model, parsed, new LinkedHashMap<>(raw), approximations);
    }

    // ---- the agent handle --------------------------------------------------------------------------------------------------

    /** Inputs of {@link Agent#fromPrincipal}. {@code principal}, {@code goal} and {@code permissions} are required. */
    public static final class AgentOptions {
        public final Keys.SuiteKey principal;
        public final String goal;
        public final Map<String, Object> permissions;
        Map<String, Object> limits, agentBinding, riskPolicy;
        Keys.SuiteKey holder;
        String budgetModel, aud, goalSalt;
        Catalog catalog;
        Long now;
        ArgProvenance.Recorder recorder;

        public AgentOptions(Keys.SuiteKey principal, String goal, Map<String, Object> permissions) {
            this.principal = principal;
            this.goal = goal;
            this.permissions = permissions;
        }

        /** Per-action limits, e.g. {@code {"refund": "$500/day"}}. */
        public AgentOptions limits(Map<String, Object> v) { limits = v; return this; }
        /** The agent (holder) key that signs actions; generated (Ed25519) when not given. A PQ suite key commits its {@code pq_pk} in the grant. */
        public AgentOptions holder(Keys.SuiteKey v) { holder = v; return this; }
        /** The agent-identity binding (model, weights, operator pins); {@code {}} when not given. */
        public AgentOptions agentBinding(Map<String, Object> v) { agentBinding = v; return this; }
        /** Members that override the derived risk policy. */
        public AgentOptions riskPolicy(Map<String, Object> v) { riskPolicy = v; return this; }
        /** {@code auto} (default: dollars when any {@code $} limit is given), {@code dollars} or {@code risk}. */
        public AgentOptions budgetModel(String v) { budgetModel = v; return this; }
        public AgentOptions catalog(Catalog v) { catalog = v; return this; }
        /** The default audience (resource server or instance id) of {@code act}. */
        public AgentOptions aud(String v) { aud = v; return this; }
        /** The clock (ms) for minting and limit windows; the wall clock when not given. */
        public AgentOptions now(long v) { now = v; return this; }
        /** The goal commitment's salt; random when not given. Pass one only to reproduce a grant byte for byte. */
        public AgentOptions goalSalt(String v) { goalSalt = v; return this; }
        /**
         * The provenance recorder (mediator). Default: mediator {@code agent-harness}, kid {@code k1}, a fresh key and session. Its pin
         * is named in the grant's signed envelope. It must run in the harness, out of the model's reach.
         */
        public AgentOptions provenance(ArgProvenance.Recorder v) { recorder = v; return this; }
    }

    /** Per-call options of {@link Handle#act}; every member is optional. */
    public static final class ActOptions {
        public Long counter, now, ttlMs;
        public String aud, nonce;
        /** Agent uncertainty in [0,1] (a {@link Json.Num} for a fraction): can only raise the verifier's risk. */
        public Object caution;
        /** The risk claimed for this action, overriding the one derived from the catalog. */
        public Double risk;
    }

    /** The local, advisory pre-check of an action. {@code t} is the risk tier admission would assign (1 auto, 2, 3 human co-sign). */
    public static final class DryRun {
        public final boolean allowed;
        public final String reason;
        public final Integer t;
        DryRun(boolean allowed, String reason, Integer t) { this.allowed = allowed; this.reason = reason; this.t = t; }
    }

    /** What {@link Handle#act} returns. {@code headers} carries {@code PCA-Action} and (when it fits) {@code PCA-Provenance}. */
    public static final class ActResult {
        public final Map<String, Object> pcactn;
        public final String encoded;
        public final Map<String, String> headers;
        public final DryRun dryRun;
        public final Map<String, Object> provenance;
        ActResult(Map<String, Object> pcactn, String encoded, Map<String, String> headers, DryRun dryRun, Map<String, Object> provenance) {
            this.pcactn = pcactn; this.encoded = encoded; this.headers = headers; this.dryRun = dryRun; this.provenance = provenance;
        }
    }

    /** Build an agent: compile the inputs, create the recorder, mint the grant (see {@link Agent#fromPrincipal}). */
    public static Handle agent(AgentOptions o) {
        Catalog cat = o.catalog != null ? o.catalog : Catalog.DEFAULT;
        long now = o.now != null ? o.now : System.currentTimeMillis();
        Keys.SuiteKey holder = o.holder != null ? o.holder : Keys.ed25519(Keys.edGenerate());
        if (holder.ed == null) throw new IllegalArgumentException("agent: the holder needs an Ed25519 identity");
        if (o.principal == null || o.principal.ed == null) throw new IllegalArgumentException("agent: the principal needs an Ed25519 identity");
        CompiledPolicy policy = compilePolicy(o.permissions, o.limits, cat, o.budgetModel, o.riskPolicy, now);
        ArgProvenance.Recorder rec = o.recorder != null ? o.recorder : ArgProvenance.Recorder.create("agent-harness", "k1");
        List<Object> mediators = new ArrayList<>();
        mediators.add(new LinkedHashMap<>(rec.pin()));
        Map<String, Object> env = Issue.obj("predicates", policy.predicates, "caveats", policy.caveats,
            "agent_binding", o.agentBinding != null ? o.agentBinding : new LinkedHashMap<String, Object>(), "risk_policy", policy.riskPolicy,
            "provenance", Issue.obj("mediators", mediators));
        Issue.Grant g = Issue.mintGrant(o.principal, holder.ed.id(), holder.pqPk(), env, o.goal, o.goalSalt);
        List<Object> chain = new ArrayList<>();
        chain.add(g.grant);
        return new Handle(g.grant, chain, g.goalSalt, policy, holder, o.principal.ed.id(), cat, o.aud, now, rec);
    }

    /** An agent under a facade-minted grant: it builds one proof-carrying action per call. Not thread-safe (one counter). */
    public static final class Handle {
        public final Map<String, Object> grant;
        /** The capability chain: the grant first, one more hop per sub-agent. */
        public final List<Object> chain;
        /** The salt that opens the grant's goal commitment (keep it with the goal). */
        public final String goalSalt;
        public final CompiledPolicy policy;
        /** The agent key: it signs actions and never leaves the client. */
        public final Keys.SuiteKey holder;
        public final String principalPublic;
        /** The provenance recorder: record the principal's messages and every tool, retrieval and web result the model reads. */
        public final ArgProvenance.Recorder provenance;
        private final Catalog catalog;
        private final String defaultAud;
        private final long startNow;
        private long counter;

        Handle(Map<String, Object> grant, List<Object> chain, String goalSalt, CompiledPolicy policy, Keys.SuiteKey holder, String principalPublic,
               Catalog catalog, String defaultAud, long startNow, ArgProvenance.Recorder provenance) {
            this.grant = grant; this.chain = chain; this.goalSalt = goalSalt; this.policy = policy; this.holder = holder;
            this.principalPublic = principalPublic; this.catalog = catalog; this.defaultAud = defaultAud; this.startNow = startNow; this.provenance = provenance;
        }

        private double kappa() { return Caveats.fin(policy.riskPolicy.get("kappa")); }
        private double bMax() { return Caveats.fin(policy.riskPolicy.get("bMax")); }

        /** The starting trust budget {@code {B = bMax, tau, asOf}} (metered by the server; exposed for planning). */
        public Map<String, Object> budget() { return Issue.obj("B", jn(bMax()), "tau", startNow, "asOf", startNow); }

        /** The most this agent can do between human co-signs: {@code bMax / kappa * kappa}. */
        public double autonomyBound() {
            double k = kappa();
            return (k > 0 ? Math.max(0, bMax()) / k : 0) * k;
        }

        /** The grant as canonical JSON (for transport or inspection). */
        public String encodeGrant() { return Json.canonicalize(grant); }

        private double riskFor(Catalog.Spec spec, Map<String, Object> params, Double override) {
            if (override != null) return Math.max(0, Math.min(1, override));
            if ("dollars".equals(policy.budgetModel) && spec.amountField != null) {
                double amt = jsNumber(params, spec.amountField);
                if (!Double.isNaN(amt) && !Double.isInfinite(amt) && kappa() > 0) return Math.max(0, Math.min(1, amt / kappa()));
            }
            return Math.max(0, Math.min(1, spec.blastRadius));
        }

        /** JavaScript {@code Number(params[field])} for the JSON values a param can hold. */
        private static double jsNumber(Map<String, Object> params, String field) {
            if (params == null || !params.containsKey(field)) return Double.NaN;
            Object v = params.get(field);
            if (v == null) return 0;
            if (v instanceof Boolean) return (Boolean) v ? 1 : 0;
            Double n = IntentJs.num(v);
            if (n != null) return n;
            if (v instanceof String) {
                String t = jsTrim((String) v);
                if (t.isEmpty()) return 0;
                try { return Double.parseDouble(t); } catch (NumberFormatException e) { return Double.NaN; }
            }
            return Double.NaN;
        }

        /** Local, advisory pre-check of the grant's own predicates and caveats, plus the risk tier. Never authoritative. */
        public DryRun dryRun(String verb, String resource, Map<String, Object> params, Long now) {
            Catalog.Spec spec = specFor(catalog, verb);
            long t = now != null ? now : System.currentTimeMillis();
            Map<String, Object> ctx = Issue.obj("action", Issue.obj("verb", verb, "resource", resource,
                "params", params != null ? params : new LinkedHashMap<String, Object>(), "reversibility_class", spec.reversibility));
            if (!Predicates.evaluatePredicates(policy.predicates, ctx)) return new DryRun(false, "no predicate permits " + verb + " on " + resource, null);
            // the local handle has no admitted-action history (the server meters it), so a rate caveat is checked against none
            Map<String, Object> cctx = Issue.obj("now", t, "blast_radius", spec.blastRadius, "reversibility_class", spec.reversibility,
                "delegation_depth", (long) (chain.size() - 1), "recent_action_times", new ArrayList<Object>());
            Caveats.Result cav = Caveats.evaluateCaveats(policy.caveats, cctx);
            if (!cav.ok) return new DryRun(false, "caveat(s) failed: " + String.join(", ", cav.failed), null);
            double r = riskFor(spec, params, null);
            int tier = Risk.requiredThreshold(r, Caveats.fin(policy.riskPolicy.get("theta1")), Caveats.fin(policy.riskPolicy.get("theta2")), false).t;
            return new DryRun(true, null, Risk.admit(tier, bMax() >= Risk.cost(r, kappa())).t);
        }

        /**
         * Build a proof-carrying action: a one-node plan ({@code n0}, the catalog's reversibility, the params digest), the risk claim,
         * the counter (the next one unless {@code o.counter} is given) and no nonce unless {@code o.nonce} is given. Records the
         * action with the provenance recorder and returns the bundle. Does NOT authorize anything.
         */
        public ActResult act(String verb, String resource, Map<String, Object> params, ActOptions o) {
            ActOptions op = o != null ? o : new ActOptions();
            String aud = op.aud != null ? op.aud : defaultAud;
            if (aud == null || aud.isEmpty()) throw new IllegalArgumentException("act: aud (resource-server / instance id) is required (pass opts.aud or AgentOptions.aud)");
            Catalog.Spec spec = specFor(catalog, verb);
            Map<String, Object> node = Issue.obj("id", "n0", "verb", verb, "resource", resource, "reversibility_class", spec.reversibility, "params_digest", Pca.paramsDigest(params));
            double r = riskFor(spec, params, op.risk);
            long use;
            if (op.counter != null) {
                use = op.counter;
                counter = Math.max(counter, op.counter);
            } else use = ++counter;
            List<Map<String, Object>> nodes = new ArrayList<>();
            nodes.add(node);
            Issue.ActSpec s = new Issue.ActSpec();
            s.grant = grant;
            s.chain = chain;
            s.plan = Issue.commitPlan(nodes);
            s.nodeId = "n0";
            s.params = params;
            s.counter = use;
            s.signer = holder;
            s.aud = aud;
            s.iat = op.now != null ? op.now : System.currentTimeMillis();
            s.ttlMs = op.ttlMs;
            s.nonce = op.nonce;
            s.caution = op.caution;
            s.riskClaim = Issue.obj("r", jn(r), "inputs", Issue.obj("blastRadius", jn(r)));
            Map<String, Object> pcactn = Issue.buildPCActn(s);
            Map<String, Object> bundle = provenance.forAction(new Authorize.Operation(verb, resource, params != null ? params : new LinkedHashMap<String, Object>()));
            return new ActResult(pcactn, Issue.encode(pcactn), Issue.headers(pcactn, null, null, null, null, bundle), dryRun(verb, resource, params, op.now), bundle);
        }

        /**
         * A sub-agent: one more (attenuated) hop signed by this agent's key. With no {@code child}, a key is generated: Ed25519, or for a
         * post-quantum holder a fresh key of the same suite (never this agent's PQ key), whose {@code pq_pk} is committed in the hop.
         */
        public Handle subAgent(Keys.SuiteKey child, List<Object> addedCaveats) {
            Keys.SuiteKey c = child;
            if (c == null) c = holder.pq == null ? Keys.ed25519(Keys.edGenerate()) : Keys.suite(holder.alg, Keys.edGenerate(), Keys.pqGenerate(holder.pq.prim));
            if (c.ed == null) throw new IllegalArgumentException("subAgent: the sub-agent needs an Ed25519 identity");
            Map<String, Object> leaf = Pca.asMap(chain.get(chain.size() - 1));
            Map<String, Object> hop = Issue.delegate(leaf, c.ed.id(), addedCaveats, holder, c.pqPk());
            List<Object> ch = new ArrayList<>(chain);
            ch.add(hop);
            return new Handle(grant, ch, goalSalt, policy, c, principalPublic, catalog, defaultAud, startNow, provenance);
        }
    }
}
