package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import net.atlasauth.pca.intent.IntentCompilers;
import net.atlasauth.pca.research.PolicySim;

/**
 * The approval half of natural-language policy authoring. The model's completion is parsed strictly and grounded in the catalog, the draft is
 * content-addressed and bound to the instruction, the model and the exact prompt, a pinned reviewer signs the digest, and only a verified,
 * unexpired approval compiles into an agent. The model is an injected {@code complete(prompt)}; this SDK adds no model dependency. A draft is
 * never authority: {@link #loadApprovedPolicy} refuses a tampered, unknown-verb, unreviewed or expired one, and {@link #agentFromApprovedNL}
 * mints a grant only from an approved policy for the goal the reviewer saw.
 */
public final class NlApproval {
    private NlApproval() {}

    public static final String NL_APPROVAL_DOMAIN = "atlas-pca/nl-approval/v1\0";
    public static final String NL_APPROVAL_DOMAIN_V2 = "atlas-pca/nl-approval/v2\0";
    /** The most UTF-8 bytes of model output a draft accepts. */
    public static final int MAX_NL_OUTPUT_BYTES = 16_384;
    /** The longest an approval may live (24 hours). */
    public static final long MAX_NL_APPROVAL_TTL_MS = 24L * 3_600_000L;
    private static final long DEFAULT_NL_APPROVAL_TTL_MS = 3_600_000L;

    private static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    private static Catalog catalogOf(Catalog c) { return c != null ? c : Catalog.DEFAULT; }

    private static String hashLenient(Object v) { return StoreJs.hashLenient(IntentJs.normalize(v)); }

    /**
     * The digest of a catalog as the NL layer sees it: SHA-256 of the lenient canonical rows {@code [verb, reversibility, amountField|null]}
     * sorted by verb. Not the catalog module's own digest.
     */
    public static String catalogDigest(Catalog catalog) {
        List<List<Object>> rows = new ArrayList<>();
        for (Catalog.Spec s : catalogOf(catalog).all()) {
            List<Object> r = new ArrayList<>();
            r.add(s.verb);
            r.add(s.reversibility);
            r.add(s.amountField);
            rows.add(r);
        }
        rows.sort((a, b) -> ((String) a.get(0)).compareTo((String) b.get(0)));
        return hashLenient(Issue.obj("v", IntentJs.ofLong(1), "rows", new ArrayList<Object>(rows)));
    }

    /** The binding of a draft: {@code {instruction_digest, model, prompt_digest}} (the model is null when none). */
    public static Map<String, Object> draftBinding(String instruction, Catalog catalog, String model) {
        return Issue.obj("instruction_digest", hashLenient(Issue.obj("d", "atlas-pca/nl-instruction/v1", "text", instruction)), "model", model,
            "prompt_digest", hashLenient(Issue.obj("d", "atlas-pca/nl-prompt/v1", "text", IntentCompilers.nlPrompt(instruction, catalogOf(catalog)))));
    }

    private static List<Object> jsSorted(Object v) {
        List<Object> out = new ArrayList<>();
        if (v instanceof List) out.addAll((List<?>) v);
        else if (v instanceof String) ((String) v).codePoints().forEach(c -> out.add(new String(Character.toChars(c))));
        else throw new IllegalArgumentException("object is not iterable");
        out.sort((a, b) -> IntentRevocation.jsText(a, true).compareTo(IntentRevocation.jsText(b, true)));
        return out;
    }

    private static Map<String, Object> sortedPermissions(Map<String, Object> permissions) {
        List<String> keys = new ArrayList<>(permissions.keySet());
        keys.sort(String::compareTo);
        Map<String, Object> perms = new LinkedHashMap<>();
        for (String c : keys) perms.put(c, jsSorted(permissions.get(c)));
        return perms;
    }

    /** The v2 draft digest: permissions (connectors and actions sorted), limits, the catalog digest and the binding. */
    public static String draftDigestV2(Map<String, Object> permissions, Object limits, String catalogDigest, Map<String, Object> binding) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", IntentJs.ofLong(2));
        m.put("permissions", sortedPermissions(permissions));
        m.put("limits", limits);
        m.put("catalog_digest", catalogDigest);
        m.put("instruction_digest", binding.get("instruction_digest"));
        m.put("model", binding.get("model"));
        m.put("prompt_digest", binding.get("prompt_digest"));
        return hashLenient(m);
    }

    /** The v1 (pre-binding) draft digest: no instruction, model or prompt. */
    public static String draftDigest(Map<String, Object> permissions, Object limits, String catalogDigest) {
        return hashLenient(Issue.obj("v", IntentJs.ofLong(1), "permissions", sortedPermissions(permissions), "limits", limits, "catalog_digest", catalogDigest));
    }

    private static List<Object> lintsOf(Map<String, Object> permissions, Map<String, Object> limits, Catalog catalog) {
        if (permissions.isEmpty()) return new ArrayList<>();
        return PolicySim.lintPolicy(Facade.compilePolicy(permissions, limits, catalog, null, null, 0L), catalog);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parse(String raw, Catalog catalog) { return IntentCompilers.parseNLPolicy(raw, catalog); }

    /**
     * Ask the model for a policy and parse it strictly: {@code {permissions, limits, unknownVerbs, droppedLimits, raw, lints}}. Verbs outside the
     * catalog and limits that do not parse or name no granted action are dropped and reported. A throwing model throws.
     */
    public static Map<String, Object> policyFromNL(String instruction, Function<String, String> complete, Catalog catalog, String model) {
        Catalog cat = catalogOf(catalog);
        String raw = complete.apply(IntentCompilers.nlPrompt(instruction, cat));
        Map<String, Object> parsed = parse(raw, cat);
        Map<String, Object> out = new LinkedHashMap<>(parsed);
        out.put("raw", raw);
        out.put("lints", lintsOf(StoreJs.map(parsed.get("permissions")), StoreJs.map(parsed.get("limits")), cat));
        return out;
    }

    /**
     * {@link #policyFromNL} as a reviewable DRAFT: content-addressed (digest v2 over the policy, the catalog and the binding to the instruction,
     * model and prompt) with the analyzer's verdict. Throws when the model fails or its output exceeds 16384 UTF-8 bytes.
     */
    public static Map<String, Object> draftPolicyFromNL(String instruction, Function<String, String> complete, Catalog catalog, String model) {
        Catalog cat = catalogOf(catalog);
        String raw = complete.apply(IntentCompilers.nlPrompt(instruction, cat));
        if (raw == null || raw.getBytes(StandardCharsets.UTF_8).length > MAX_NL_OUTPUT_BYTES) {
            throw new IllegalArgumentException("draftPolicyFromNL: model output exceeds " + MAX_NL_OUTPUT_BYTES + " bytes or is not a string");
        }
        Map<String, Object> p = parse(raw, cat);
        Map<String, Object> permissions = StoreJs.map(p.get("permissions")), limits = StoreJs.map(p.get("limits"));
        List<Object> lints = lintsOf(permissions, limits, cat);
        String cd = catalogDigest(cat);
        Map<String, Object> binding = draftBinding(instruction, cat, model);
        boolean hasError = false;
        for (Object l : lints) if ("error".equals(get(l, "level"))) hasError = true;
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("status", "draft");
        d.put("instruction", instruction);
        d.put("permissions", permissions);
        d.put("limits", limits);
        d.put("catalog_digest", cd);
        d.put("binding", binding);
        d.put("digest", draftDigestV2(permissions, limits, cd, binding));
        d.put("unknownVerbs", p.get("unknownVerbs"));
        d.put("droppedLimits", p.get("droppedLimits"));
        d.put("lints", lints);
        d.put("analyzerOk", !permissions.isEmpty() && !hasError);
        return d;
    }

    private static byte[] approvalMessage(Object v, Object digest, Object catalogDigest, Object reviewer, Object approvedAt, Object expiresAt) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("v", v);
        body.put("digest", digest);
        body.put("catalog_digest", catalogDigest);
        body.put("reviewer", reviewer);
        body.put("approved_at", approvedAt);
        body.put("expires_at", expiresAt);
        String domain = IntentJs.num(v) != null && IntentJs.num(v) == 2 ? NL_APPROVAL_DOMAIN_V2 : NL_APPROVAL_DOMAIN;
        return Pca.concat(domain.getBytes(StandardCharsets.UTF_8), Json.utf8(Json.canonicalize(IntentJs.normalize(body))));
    }

    private static Map<String, Object> sign(long version, Object digest, Object catalogDigest, byte[] reviewerSecret, double now, double ttl) {
        String reviewer = Keys.edFromSeed(reviewerSecret).id();
        Object approvedAt = StoreJs.num(now), expiresAt = StoreJs.num(now + ttl);
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("v", IntentJs.ofLong(version));
        a.put("digest", digest);
        a.put("catalog_digest", catalogDigest);
        a.put("reviewer", reviewer);
        a.put("approved_at", approvedAt);
        a.put("expires_at", expiresAt);
        a.put("sig", Pca.b64(Keys.edFromSeed(reviewerSecret).sign(approvalMessage(a.get("v"), digest, catalogDigest, reviewer, approvedAt, expiresAt))));
        return a;
    }

    private static double[] window(Map<String, Object> opts) {
        Double now = opts != null && opts.get("now") != null ? IntentJs.num(opts.get("now")) : Double.valueOf(System.currentTimeMillis());
        Double ttl = opts != null && opts.get("ttlMs") != null ? IntentJs.num(opts.get("ttlMs")) : Double.valueOf(DEFAULT_NL_APPROVAL_TTL_MS);
        if (now == null || ttl == null || Double.isNaN(now) || Double.isInfinite(now) || Double.isNaN(ttl) || Double.isInfinite(ttl) || ttl <= 0 || ttl > MAX_NL_APPROVAL_TTL_MS) {
            throw new IllegalArgumentException("approveDraft: invalid time or ttl");
        }
        return new double[] {now, ttl};
    }

    /** JavaScript ToNumber of a JSON scalar (a string is parsed, an empty one is 0, anything else unparsable is NaN). */
    private static double jsNumber(Object v) {
        Double d = IntentJs.num(v);
        if (d != null) return d;
        if (v instanceof Boolean) return (Boolean) v ? 1 : 0;
        if (v instanceof String) {
            String t = ((String) v).strip();
            if (t.isEmpty()) return 0;
            try { return t.matches("[+-]?(\\d+\\.?\\d*([eE][+-]?\\d+)?|\\.\\d+([eE][+-]?\\d+)?)") ? Double.parseDouble(t) : Double.NaN; } catch (NumberFormatException e) { return Double.NaN; }
        }
        return Double.NaN;
    }

    private static void checkApprovable(Map<String, Object> draft) {
        if (!IntentRevocation.truthy(draft.get("analyzerOk"))) throw new IllegalArgumentException("approveDraft: the draft did not pass the static analyzer");
        Object unknown = draft.get("unknownVerbs");
        if (!(unknown instanceof List)) throw new IllegalArgumentException("Cannot read properties of undefined (reading 'length')");
        if (!((List<?>) unknown).isEmpty()) throw new IllegalArgumentException("approveDraft: the draft proposed verbs that are not in the catalog");
    }

    /**
     * Approve a draft as a pinned reviewer: a v2 approval {@code {v, digest, catalog_digest, reviewer, approved_at, expires_at, sig}} over the
     * draft's digest. {@code opts = {now, ttlMs}} (the clock defaults to the system clock; the ttl to one hour and is at most 24 hours). Throws
     * for a draft that failed the analyzer or proposed verbs outside the catalog.
     */
    public static Map<String, Object> approveDraft(Map<String, Object> draft, byte[] reviewerSecret, Map<String, Object> opts) {
        checkApprovable(draft);
        double[] w = window(opts);
        return sign(2, draft.get("digest"), draft.get("catalog_digest"), reviewerSecret, w[0], w[1]);
    }

    /**
     * The pre-0.5 approval (v1): it signs the draft WITHOUT the instruction, model or prompt. For the legacy-load compatibility window only;
     * {@link #loadApprovedPolicy} reports it as {@code legacy_unbound_instruction}.
     */
    public static Map<String, Object> approveDraftLegacyV1(Map<String, Object> draft, byte[] reviewerSecret, Map<String, Object> opts) {
        checkApprovable(draft);
        double[] w = window(opts);
        String digest = draftDigest(StoreJs.map(draft.get("permissions")), StoreJs.map(draft.get("limits")), (String) draft.get("catalog_digest"));
        return sign(1, digest, draft.get("catalog_digest"), reviewerSecret, w[0], w[1]);
    }

    private static Map<String, Object> fail(String reason) { return Issue.obj("ok", false, "reason", reason); }

    /**
     * Load an approved policy: the draft is a draft of THIS catalog, untampered (its digest, and for a bound draft its instruction, model and
     * prompt), proposes only catalog verbs, is non-empty and passes the analyzer; the approval is well formed, covers this digest and catalog,
     * names a pinned reviewer, lives at most 24 hours, is valid now and verifies under the reviewer key. {@code opts = {reviewers, catalog?, now?}}
     * ({@code catalog} a {@link Catalog}). Returns {@code {ok: true, permissions, limits, reviewer, instruction, legacy_unbound_instruction}} or
     * {@code {ok: false, reason}} with the reason one of the NL rejection codes. Never throws.
     */
    public static Map<String, Object> loadApprovedPolicy(Map<String, Object> draft, Map<String, Object> approval, Map<String, Object> opts) {
        try {
            Catalog catalog = opts.get("catalog") instanceof Catalog ? (Catalog) opts.get("catalog") : Catalog.DEFAULT;
            double now = opts.get("now") != null ? jsNumber(opts.get("now")) : System.currentTimeMillis();
            Object reviewers = opts.get("reviewers");
            if (!(reviewers instanceof List) || ((List<?>) reviewers).isEmpty()) return fail("no_reviewers_pinned");
            if (draft == null || !"draft".equals(draft.get("status")) || !(draft.get("permissions") instanceof Map) || !(draft.get("limits") instanceof Map || draft.get("limits") instanceof List)) return fail("not_a_draft");
            // an array is an object for the reference's type check (its digest then differs from the draft's)
            Object limits = draft.get("limits");
            Map<String, Object> permissions = StoreJs.map(draft.get("permissions"));
            String cd = catalogDigest(catalog);
            if (!cd.equals(draft.get("catalog_digest"))) return fail("catalog_mismatch");
            if (!(draft.get("instruction") instanceof String)) return fail("not_a_draft");
            boolean legacyDraft = !draft.containsKey("binding");
            if (!legacyDraft && !(draft.get("binding") instanceof Map)) return fail("not_a_draft");
            if (legacyDraft) {
                if (!draftDigest(permissions, limits, cd).equals(draft.get("digest"))) return fail("tampered_draft");
            } else {
                Map<String, Object> have = StoreJs.map(draft.get("binding"));
                Map<String, Object> binding = draftBinding((String) draft.get("instruction"), catalog, have.get("model") instanceof String ? (String) have.get("model") : null);
                if (!Ledger.jsEq(have.get("instruction_digest"), binding.get("instruction_digest")) || !Ledger.jsEq(have.get("prompt_digest"), binding.get("prompt_digest"))
                    || !have.containsKey("model") || !Ledger.jsEq(have.get("model"), binding.get("model"))) return fail("tampered_draft");
                if (!draftDigestV2(permissions, limits, cd, binding).equals(draft.get("digest"))) return fail("tampered_draft");
            }
            for (Map.Entry<String, Object> e : permissions.entrySet()) {
                if (!(e.getValue() instanceof List)) return fail("unknown_verbs");
                for (Object a : (List<?>) e.getValue()) if (!(a instanceof String) || catalog.get(e.getKey() + "." + a) == null) return fail("unknown_verbs");
            }
            if (draft.get("unknownVerbs") instanceof List && !((List<?>) draft.get("unknownVerbs")).isEmpty()) return fail("unknown_verbs");
            if (permissions.isEmpty()) return fail("empty_permissions");
            for (Object l : lintsOf(permissions, limits instanceof Map ? StoreJs.map(limits) : new LinkedHashMap<String, Object>(), catalog)) if ("error".equals(get(l, "level"))) return fail("analyzer_error");
            if (approval == null) return fail("malformed_approval");
            Object av = approval.get("v");
            boolean v1 = IntentJs.num(av) != null && IntentJs.num(av) == 1, v2 = IntentJs.num(av) != null && IntentJs.num(av) == 2;
            if ((!v1 && !v2) || !(approval.get("sig") instanceof String) || !(approval.get("reviewer") instanceof String) || !(approval.get("digest") instanceof String)
                || !(approval.get("catalog_digest") instanceof String) || !IntentJs.isInt(approval.get("approved_at")) || !IntentJs.isInt(approval.get("expires_at"))) return fail("malformed_approval");
            if (legacyDraft && !v1) return fail("digest_mismatch"); // a v2 approval promises the instruction is bound; a binding-less draft cannot honor that
            Object want = v1 ? draftDigest(permissions, limits, cd) : draft.get("digest");
            if (!approval.get("digest").equals(want) || !approval.get("catalog_digest").equals(cd)) return fail("digest_mismatch");
            if (!((List<?>) reviewers).contains(approval.get("reviewer"))) return fail("reviewer_not_pinned");
            double approvedAt = IntentJs.num(approval.get("approved_at")), expiresAt = IntentJs.num(approval.get("expires_at"));
            if (expiresAt - approvedAt <= 0 || expiresAt - approvedAt > MAX_NL_APPROVAL_TTL_MS) return fail("ttl_too_long");
            if (approvedAt > now) return fail("not_yet_valid");
            if (now >= expiresAt) return fail("expired");
            byte[] msg = approvalMessage(av, approval.get("digest"), approval.get("catalog_digest"), approval.get("reviewer"), approval.get("approved_at"), approval.get("expires_at"));
            if (!IntentJs.verifyEd(approval.get("reviewer"), msg, approval.get("sig"))) return fail("bad_signature");
            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("ok", true);
            ok.put("permissions", permissions);
            ok.put("limits", limits);
            ok.put("reviewer", approval.get("reviewer"));
            ok.put("instruction", draft.get("instruction"));
            ok.put("legacy_unbound_instruction", v1);
            return ok;
        } catch (RuntimeException e) {
            return fail("malformed_approval");
        }
    }

    /** What {@link #agentFromApprovedNL} returns. */
    public static final class ApprovedAgent {
        public final Facade.Handle agent;
        public final String reviewer;
        public final boolean legacyUnboundInstruction;

        ApprovedAgent(Facade.Handle agent, String reviewer, boolean legacy) { this.agent = agent; this.reviewer = reviewer; this.legacyUnboundInstruction = legacy; }
    }

    /**
     * Mint an agent from an approved NL policy. {@code opts} are those of {@link #loadApprovedPolicy}; the goal must be the instruction the
     * reviewer saw (a legacy v1 approval, which never bound it, is exempt and reported). Throws {@code agentFromApprovedNL: <reason>} for a
     * rejected approval or a different goal. {@code aud} and {@code holder} are optional.
     */
    public static ApprovedAgent agentFromApprovedNL(Map<String, Object> draft, Map<String, Object> approval, Map<String, Object> opts, Keys.SuiteKey principal, String goal,
                                                    String aud, Keys.SuiteKey holder) {
        Map<String, Object> loaded = loadApprovedPolicy(draft, approval, opts);
        if (!Boolean.TRUE.equals(loaded.get("ok"))) throw new IllegalArgumentException("agentFromApprovedNL: " + loaded.get("reason"));
        boolean legacy = Boolean.TRUE.equals(loaded.get("legacy_unbound_instruction"));
        if (!legacy && !goal.equals(loaded.get("instruction"))) throw new IllegalArgumentException("agentFromApprovedNL: goal_mismatch");
        Facade.AgentOptions o = new Facade.AgentOptions(principal, goal, StoreJs.map(loaded.get("permissions"))).limits(StoreJs.map(loaded.get("limits")));
        if (opts.get("catalog") instanceof Catalog) o.catalog((Catalog) opts.get("catalog"));
        if (aud != null) o.aud(aud);
        if (holder != null) o.holder(holder);
        if (opts.get("now") != null) o.now((long) (double) IntentJs.num(opts.get("now")));
        return new ApprovedAgent(Facade.agent(o), (String) loaded.get("reviewer"), legacy);
    }
}
