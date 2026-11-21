package net.atlasauth.pca.compliance;

import static net.atlasauth.pca.compliance.Js.UNDEF;
import static net.atlasauth.pca.compliance.Js.obj;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Pca;

/**
 * Auditor-ready compliance evidence from PCA proofs and decision records, pre-mapped to EU AI Act Art. 12 / 50, ISO/IEC 42001 and
 * SOC 2 CC6, plus the console-activity framework report (EU AI Act, SOC 2, GDPR). Everything is pure and read-only, and total where
 * the reference is: a malformed record degrades to a best-effort one. HONEST SCOPE: an evidence mapping, not a legal certification.
 * Inputs and outputs are the JSON shapes (Map / List / String / Boolean / Json.Num / null); member reads follow JavaScript semantics.
 */
public final class Compliance {
    private Compliance() {}

    public static final List<String> COMPLIANCE_FRAMEWORKS = List.of("eu-ai-act", "iso-42001", "soc2");
    public static final List<Map<String, Object>> CONTROL_MAPPINGS = ControlTable.MAPPINGS;
    private static final List<String> FRAMEWORK_IDS = List.of("eu-ai-act", "soc2", "gdpr");

    // ---- AuditEvent ----

    private static boolean isBudgetAlloc(Object cv) {
        if (!(cv instanceof Map)) return false;
        Map<?, ?> m = (Map<?, ?>) cv;
        return "budget_alloc".equals(m.get("type")) && Js.finite(m.get("limit")) && Js.num(m.get("limit")) >= 0;
    }

    private static String numstr(Object x) {
        if (!Js.finite(x)) return Js.tpl(x);
        double d = Js.num(x);
        if (d == Math.rint(d)) return Js.numStr(d);
        return Js.numStr(Js.round(d * 1e4) / 1e4);
    }

    /** A bounded, human-readable rendering of one caveat. */
    @SuppressWarnings("unchecked")
    public static String describeCaveat(Object cv) {
        if (!(cv instanceof Map) || !(((Map<?, ?>) cv).get("type") instanceof String)) return "(malformed caveat)";
        Map<String, Object> m = (Map<String, Object>) cv;
        String type = (String) m.get("type");
        if (type.equals("envelope")) {
            Object p = m.get("predicates"), c = m.get("caveats");
            return "policy envelope (" + (p instanceof List ? ((List<?>) p).size() : 0) + " predicate(s), " + (c instanceof List ? ((List<?>) c).size() : 0) + " caveat(s))";
        }
        if (isBudgetAlloc(cv)) return "budget allocation ≤ " + numstr(m.get("limit"));
        List<String> parts = new ArrayList<>();
        List<String> ks = Js.keys(m);
        for (String k : ks.subList(0, Math.min(8, ks.size()))) {
            if (k.equals("type")) continue;
            Object v = m.get(k);
            parts.add(k + "=" + (v instanceof Map || v instanceof List ? Js.stringify(v, "", false) : numstr(v)));
        }
        return parts.isEmpty() ? type : type + "(" + String.join(", ", parts) + ")";
    }

    @SuppressWarnings("unchecked")
    private static List<Object> buildDelegationHops(Object chain) {
        List<Object> safe = chain instanceof List ? (List<Object>) chain : List.of();
        List<Object> hops = new ArrayList<>();
        for (int i = 0; i < safe.size(); i++) {
            Object cap = safe.get(i);
            if (!Js.truthy(cap)) continue;
            boolean isRoot = i == 0;
            Object parent = i > 0 ? safe.get(i - 1) : null;
            Object pcv = Js.truthy(parent) ? Js.own(parent, "caveats") : UNDEF;
            int parentLen = pcv instanceof List ? ((List<?>) pcv).size() : 0;
            Object ownCv = Js.own(cap, "caveats");
            List<Object> own = ownCv instanceof List ? (List<Object>) ownCv : List.of();
            List<Object> added = isRoot ? own : own.size() >= parentLen ? own.subList(parentLen, own.size()) : List.of();
            List<Object> scope = new ArrayList<>();
            Object budgetCv = null;
            for (Object c : added) { scope.add(describeCaveat(c)); if (budgetCv == null && isBudgetAlloc(c)) budgetCv = c; }
            Object issuer = Js.own(cap, "issuer"), holder = Js.own(cap, "holder");
            String joined = String.join("; ", scope.stream().map(String::valueOf).toArray(String[]::new));
            String narrative = isRoot
                ? "Principal " + Js.shortKey(issuer, 12) + " granted authority to " + Js.shortKey(holder, 12) + (scope.isEmpty() ? "" : " under: " + joined) + "."
                : Js.shortKey(issuer, 12) + " delegated to " + Js.shortKey(holder, 12) + (scope.isEmpty() ? " (rebind only, no new constraints)" : ", narrowing scope: " + joined) + ".";
            Map<String, Object> hop = obj("index", (long) i, "isRoot", isRoot, "issuer", issuer, "holder", holder, "scope", scope, "caveats", new ArrayList<>(added), "narrative", narrative);
            if (budgetCv != null) hop.put("budgetAlloc", ((Map<String, Object>) budgetCv).get("limit"));
            hops.add(hop);
        }
        return hops;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> buildHumanOverride(Object threshold, Object requiredTier, Object thresholdCheck) {
        Object sh = Js.truthy(threshold) ? Js.own(threshold, "shares") : UNDEF;
        List<Object> shares = sh instanceof List ? (List<Object>) sh : List.of();
        if (shares.isEmpty()) return null;
        // The threshold block is outside the signed body: never report a signed approval from unverified shares.
        if (!"pass".equals(thresholdCheck)) {
            return obj("humanApproved", false, "approvers", new ArrayList<>(), "guardianCosigners", new ArrayList<>(), "roles", new ArrayList<>(), "requiredTier", requiredTier,
                "narrative", shares.size() + " co-signature share(s) were presented but NOT verified (threshold check: " + (Js.nullish(thresholdCheck) ? "absent" : Js.tpl(thresholdCheck))
                    + "); no human approval is recorded.");
        }
        List<Object> approvers = new ArrayList<>(), guardians = new ArrayList<>(), roles = new ArrayList<>();
        for (Object s : shares) {
            if (!Js.truthy(s) || !(Js.own(s, "role") instanceof String)) continue;
            String role = (String) Js.own(s, "role");
            roles.add(role);
            Object pk = Js.own(s, "publicKey");
            if (role.equals("principal") && pk instanceof String) approvers.add(pk);
            if (role.equals("guardian") && pk instanceof String) guardians.add(pk);
        }
        boolean approved = !approvers.isEmpty();
        String narrative = approved
            ? "Step-up approved by a signed human co-signature from principal " + Js.shortKey(approvers.get(0), 12)
                + (guardians.isEmpty() ? "" : " (plus " + guardians.size() + " guardian co-sign)") + " at tier t=" + Js.tpl(requiredTier) + "."
            : "Co-signed by " + guardians.size() + " guardian share(s) at tier t=" + Js.tpl(requiredTier) + " (no human principal signature present).";
        return obj("humanApproved", approved, "approvers", approvers, "guardianCosigners", guardians, "roles", roles, "requiredTier", requiredTier, "narrative", narrative);
    }

    private static Object firstReasonOr(Object decision, String fallback) {
        Object rs = Js.own(decision, "reasons");
        if (rs instanceof List && !((List<?>) rs).isEmpty() && ((List<?>) rs).get(0) instanceof String) return ((List<?>) rs).get(0);
        return fallback;
    }

    private static Object[] resolveOutcome(Object verify, Object decision) {
        if (!Js.truthy(verify) || !Boolean.TRUE.equals(Js.own(verify, "allow"))) {
            Object r = Js.qprop(verify, "reason");
            return new Object[] {"deny", Js.nullish(r) ? "proof failed verification" : r};
        }
        if (!Js.truthy(decision)) return new Object[] {"allow", "proof verified; no policy decision supplied"};
        if (Js.truthy(Js.own(decision, "admit"))) return new Object[] {"allow", firstReasonOr(decision, "auto-admitted within policy and budget")};
        if (Js.truthy(Js.own(decision, "releaseGuardianShare"))) return new Object[] {"step-up", firstReasonOr(decision, "policy satisfied but a co-signature is required")};
        return new Object[] {"deny", firstReasonOr(decision, "policy did not release authority (default-deny)")};
    }

    private static String safeDigest(Object p) {
        if (p == UNDEF) return "(undigestible)";
        try { return Pca.hashCanonical(p); } catch (RuntimeException e) { return "(undigestible)"; }
    }

    private static Object strOr(Object v, String dflt) { return v instanceof String ? v : dflt; }

    /**
     * A normalized AuditEvent from a PCActn, the core verifier's result and the policy decision. {@code input} is
     * {@code {pcactn, verify, decision?, now?, session?}}; {@code now} (epoch ms) defaults to the clock.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> toAuditEvent(Object input) {
        Object p = Js.prop(input, "pcactn");
        Object verify = Js.own(input, "verify");
        if (Js.nullish(verify)) verify = obj("allow", false, "checks", new LinkedHashMap<String, Object>());
        Object decision = Js.own(input, "decision");
        Object now = Js.own(input, "now");
        if (Js.nullish(now)) now = Js.nowMs();
        Object cc = Js.qprop(p, "cap_chain");
        List<Object> chain = cc instanceof List ? (List<Object>) cc : null;
        List<Object> hops = buildDelegationHops(chain);
        Object leaf = chain != null && !chain.isEmpty() ? chain.get(chain.size() - 1) : UNDEF;
        Object root = chain != null && !chain.isEmpty() ? chain.get(0) : UNDEF;
        Object[] res = resolveOutcome(verify, decision);
        String outcome = (String) res[0];
        Object reason = res[1];
        Object tier = Js.qprop(Js.qprop(decision, "requiredThreshold"), "t");
        Object requiredTier = Js.nullish(tier) ? (Object) 1L : tier;
        Object checksRaw = Js.own(verify, "checks");
        Map<String, Object> human = buildHumanOverride(Js.qprop(p, "threshold"), requiredTier, Js.qprop(checksRaw, "threshold"));
        Object checks = Js.nullish(checksRaw) ? new LinkedHashMap<String, Object>() : checksRaw;
        boolean cryptoOk = "pass".equals(Js.own(checks, "wire")) && "pass".equals(Js.own(checks, "leaf_signature"));

        Object action = Js.qprop(p, "action");
        String verb = (String) strOr(Js.qprop(action, "verb"), "(unknown verb)");
        String resource = (String) strOr(Js.qprop(action, "resource"), "(unknown resource)");
        String grantRef = (String) strOr(Js.qprop(p, "grant_ref"), "(none)");
        Object counter = Js.qprop(p, "counter");
        Object nonce = Js.qprop(p, "nonce");
        Object paramsDigest = strOr(Js.qprop(action, "params_digest"), "(none)");
        Map<String, Object> evidence = obj("pcactnDigest", safeDigest(p), "leafSignature", strOr(Js.qprop(p, "sig"), "(unsigned)"),
            "signatureSuite", strOr(Js.qprop(p, "alg"), "ed25519"), "planRoot", strOr(Js.qprop(Js.qprop(p, "plan"), "root"), "(none)"), "paramsDigest", paramsDigest,
            "grantRef", grantRef, "counter", Js.isNum(counter) ? counter : (Object) (-1L), "cryptographicallyVerifiable", cryptoOk);
        if (nonce instanceof String) evidence.put("nonce", nonce);

        Map<String, Object> risk = new LinkedHashMap<>();
        if (Js.truthy(decision)) {
            Object rt = Js.own(decision, "requiredThreshold");
            Object[][] kv = {{"r", Js.own(decision, "r")}, {"tier", Js.qprop(rt, "t")}, {"proof", Js.qprop(rt, "proof")}, {"budget", Js.own(decision, "budget")}};
            for (Object[] e : kv) if (e[1] != UNDEF) risk.put((String) e[0], e[1]);
        }
        String word = outcome.equals("allow") ? "ALLOWED" : outcome.equals("deny") ? "DENIED" : "STEP-UP";
        String narrative = "Agent " + Js.shortKey(Js.qprop(leaf, "holder"), 12) + " " + word + " to " + verb + " on " + resource + " (" + hops.size() + "-hop chain rooted at principal "
            + Js.shortKey(Js.qprop(root, "issuer"), 12) + "; " + (cryptoOk ? "cryptographically verifiable proof" : "proof not cryptographically verifiable")
            + (human != null && Boolean.TRUE.equals(human.get("humanApproved")) ? "; human-signed step-up" : "") + "). " + Js.tpl(reason);

        Object holder = Js.qprop(leaf, "holder");
        Object principal = Js.qprop(root, "issuer");
        Object sess = Js.own(input, "session");
        Object iat = Js.qprop(p, "iat"), exp = Js.qprop(p, "exp");
        Map<String, Object> agent = obj("holder", strOr(holder, "(none)"));
        if (principal instanceof String) agent.put("principal", principal);
        agent.put("session", Js.nullish(sess) ? grantRef : sess);
        Map<String, Object> event = obj("schema", "atlas-pca/audit-event/v1", "recordedAt", Js.ts(now), "agent", agent,
            "delegation", obj("depth", (long) Math.max(0, hops.size() - 1), "hops", hops),
            "action", obj("verb", verb, "resource", resource, "paramsDigest", paramsDigest, "reversibilityClass", strOr(Js.qprop(action, "reversibility_class"), "(unknown)"), "summary", verb + " on " + resource),
            "decision", obj("outcome", outcome, "reason", reason, "proofVerified", Boolean.TRUE.equals(Js.own(verify, "allow")), "checks", checks),
            "risk", risk, "timestamps", obj("issuedAt", Js.ts(Js.isNum(iat) ? iat : (Object) Double.NaN), "expiresAt", Js.ts(Js.isNum(exp) ? exp : (Object) Double.NaN)),
            "evidence", evidence, "narrative", narrative);
        if (human != null) event.put("humanOverride", human);
        return event;
    }

    // ---- control mappings ----

    private static void assertFramework(Object fw) {
        if (!(fw instanceof String) || !COMPLIANCE_FRAMEWORKS.contains(fw)) {
            throw new IllegalArgumentException("pca-compliance: unknown framework '" + Js.tpl(fw) + "' (have: " + String.join(", ", COMPLIANCE_FRAMEWORKS) + ")");
        }
    }

    /** The whole control-mapping table. */
    public static List<Map<String, Object>> controlMappings() { return new ArrayList<>(CONTROL_MAPPINGS); }

    /** The control mappings of one framework (throws on an unknown framework). */
    public static List<Map<String, Object>> controlMappings(Object framework) {
        assertFramework(framework);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> m : CONTROL_MAPPINGS) if (m.get("framework").equals(framework)) out.add(m);
        return out;
    }

    // ---- ComplianceReport ----

    private static final class Stats {
        long total, verifiable, denied, stepUp, allowed, humanOverrides, withChain, withPlanRoot;
        Object maxDepth = 0L;
        int agents, principals;
        Object sampleDigest = UNDEF;
    }

    private static Stats computeStats(List<Object> events) {
        Js.JsSet agents = new Js.JsSet(), principals = new Js.JsSet();
        Stats s = new Stats();
        for (Object e : events) {
            if (!Js.truthy(e)) continue;
            if (Js.truthy(Js.prop(Js.prop(e, "evidence"), "cryptographicallyVerifiable"))) s.verifiable++;
            Object outcome = Js.prop(Js.prop(e, "decision"), "outcome");
            if ("deny".equals(outcome)) s.denied++; else if ("step-up".equals(outcome)) s.stepUp++; else s.allowed++;
            if (Js.truthy(Js.qprop(Js.own(e, "humanOverride"), "humanApproved"))) s.humanOverrides++;
            Object hl = Js.length(Js.prop(Js.prop(e, "delegation"), "hops"));
            if (hl != UNDEF && (Long) hl > 0) s.withChain++;
            if (!"(none)".equals(Js.prop(Js.prop(e, "evidence"), "planRoot"))) s.withPlanRoot++;
            Object depth = Js.prop(Js.prop(e, "delegation"), "depth");
            if (Js.gt(depth, s.maxDepth)) s.maxDepth = depth;
            agents.add(Js.prop(Js.prop(e, "agent"), "holder"));
            Object principal = Js.prop(Js.prop(e, "agent"), "principal");
            if (principal != UNDEF) principals.add(principal);
            Object digest = Js.prop(Js.prop(e, "evidence"), "pcactnDigest");
            if (s.sampleDigest == UNDEF && !"(undigestible)".equals(digest)) s.sampleDigest = digest;
        }
        s.total = events.size();
        s.agents = agents.size();
        s.principals = principals.size();
        return s;
    }

    private static Object[] evaluateControl(String id, Stats s) {
        List<Object> findings = new ArrayList<>();
        String digestNote = s.sampleDigest == UNDEF ? "" : " (e.g. " + Js.shortKey(s.sampleDigest, 16) + ")";
        long t = s.total;
        if (t == 0) return new Object[] {"not-evidenced", "no actions in the reporting period", new ArrayList<Object>(List.of("no events supplied — nothing to evidence"))};
        switch (id) {
            case "eu-ai-act:art-12": {
                if (s.verifiable < t) findings.add((t - s.verifiable) + " of " + t + " entries are not cryptographically verifiable");
                return new Object[] {s.verifiable == t ? "satisfied" : "partial", t + " actions logged; " + s.verifiable + "/" + t + " cite a cryptographically verifiable proof" + digestNote, findings};
            }
            case "eu-ai-act:art-50":
                return new Object[] {"satisfied", t + " actions each disclose the acting agent, the principal (" + s.principals + " distinct) and the automated decision outcome", findings};
            case "iso-42001:A.6.2.8":
                return new Object[] {"satisfied", t + " actions each carry a decision reason + risk/tier/budget reasoning trace", findings};
            case "iso-42001:A.9.2": {
                if (s.withChain < t) findings.add((t - s.withChain) + " entries have no delegation chain");
                return new Object[] {s.withChain == t ? "satisfied" : s.withChain > 0 ? "partial" : "not-evidenced",
                    s.withChain + "/" + t + " actions carry an explicit delegation chain (max depth " + Js.tpl(s.maxDepth) + ", " + s.principals + " authorizing principal(s))", findings};
            }
            case "iso-42001:A.9.3": {
                String status, evidence;
                if (s.humanOverrides > 0) {
                    status = "satisfied";
                    evidence = s.humanOverrides + " step-up(s) approved by a signed human co-signature; " + s.stepUp + " step-up(s) and " + s.denied + " denial(s) show oversight enforced";
                } else if (s.stepUp > 0 || s.denied > 0) {
                    status = "partial";
                    evidence = "oversight boundary enforced (" + s.stepUp + " step-up(s), " + s.denied + " denial(s)) but no signed human co-signature observed in the period";
                    findings.add("no human step-up co-signature was exercised in this period");
                } else {
                    status = "partial";
                    evidence = "all actions were auto-admitted within policy; no oversight event was triggered in the period";
                    findings.add("no higher-impact action required human oversight in this period");
                }
                return new Object[] {status, evidence, findings};
            }
            case "iso-42001:A.6.2.2": {
                if (s.withPlanRoot < t) findings.add((t - s.withPlanRoot) + " entries are not bound to a committed plan root");
                return new Object[] {s.withPlanRoot == t ? "satisfied" : s.withPlanRoot > 0 ? "partial" : "not-evidenced",
                    s.withPlanRoot + "/" + t + " actions are bound to a committed plan root (intended-use binding)", findings};
            }
            case "soc2:CC6.1":
                if (s.denied > 0) findings.add(s.denied + " out-of-scope action(s) denied — access control actively enforced");
                return new Object[] {"satisfied", "deny-by-default access over " + t + " actions (" + s.allowed + " allowed, " + s.stepUp + " step-up, " + s.denied
                    + " denied); all gated by signed predicates + attenuation", findings};
            case "soc2:CC6.2": {
                if (s.withChain < t) findings.add((t - s.withChain) + " entries are not traceable to an authorizing principal");
                return new Object[] {s.withChain == t ? "satisfied" : s.withChain > 0 ? "partial" : "not-evidenced",
                    s.agents + " agent identit(ies) traceable to " + s.principals + " authorizing principal(s) via signed delegation chains", findings};
            }
            case "soc2:CC6.3": {
                boolean narrowed = Js.toNumber(s.maxDepth) >= 1;
                if (!narrowed && s.denied == 0) findings.add("no attenuating hop or denial observed in the period");
                return new Object[] {narrowed || s.denied > 0 ? "satisfied" : "partial",
                    "access narrowed by attenuation (max delegation depth " + Js.tpl(s.maxDepth) + ") and " + s.denied + " denied action(s)", findings};
            }
            default:
                return new Object[] {"not-evidenced", "no evaluator for this control", new ArrayList<Object>(List.of("unmapped control"))};
        }
    }

    /**
     * A structured ComplianceReport for {@code opts.framework} from AuditEvents: per-control status + evidence, the PCA-unique
     * assurances and a coverage summary. {@code opts.now} (epoch ms) defaults to the clock.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> toComplianceReport(Object events, Object opts) {
        Object framework = Js.prop(opts, "framework");
        assertFramework(framework);
        List<Object> list = new ArrayList<>();
        if (events instanceof List) for (Object e : (List<Object>) events) if (Js.truthy(e)) list.add(e);
        Object now = Js.own(opts, "now");
        if (Js.nullish(now)) now = Js.nowMs();
        Stats s = computeStats(list);
        List<Object> items = new ArrayList<>();
        for (Map<String, Object> m : CONTROL_MAPPINGS) {
            if (!m.get("framework").equals(framework)) continue;
            Object[] r = evaluateControl((String) m.get("controlId"), s);
            items.add(obj("controlId", m.get("controlId"), "controlTitle", m.get("controlTitle"), "clause", m.get("clause"), "framework", m.get("framework"), "status", r[0],
                "pcaEvidence", m.get("pcaEvidence"), "evidence", r[1], "findings", r[2]));
        }
        long satisfied = 0, partial = 0, notEvidenced = 0;
        for (Object i : items) {
            Object st = ((Map<String, Object>) i).get("status");
            if ("satisfied".equals(st)) satisfied++; else if ("partial".equals(st)) partial++; else if ("not-evidenced".equals(st)) notEvidenced++;
        }
        long total = items.size();
        double fraction = total > 0 ? (double) satisfied / total : 0;
        List<Double> iats = new ArrayList<>();
        for (Object e : list) {
            Object x = Js.prop(Js.prop(Js.prop(e, "timestamps"), "issuedAt"), "epochMs");
            if (Js.finite(x)) iats.add(Js.num(x));
        }
        Object from = 0L, to = 0L;
        if (!iats.isEmpty()) {
            double lo = iats.get(0), hi = iats.get(0);
            for (double d : iats) { lo = Math.min(lo, d); hi = Math.max(hi, d); }
            from = lo;
            to = hi;
        }
        long st = s.total;
        Map<String, Object> assurances = obj("cryptographicallyVerifiable", st > 0 && s.verifiable == st, "explicitDelegationChain", st > 0 && s.withChain == st,
            "signedHumanOverrides", s.humanOverrides > 0,
            "narrative", st == 0 ? "No events in scope."
                : s.verifiable + "/" + st + " entries cite a cryptographically verifiable proof; " + s.withChain + "/" + st + " carry an explicit delegation chain; "
                    + s.humanOverrides + " step-up(s) carry a signed human co-signature.");
        String summary = framework + ": " + satisfied + "/" + total + " controls satisfied" + (partial > 0 ? ", " + partial + " partial" : "")
            + (notEvidenced > 0 ? ", " + notEvidenced + " not evidenced" : "") + " over " + st + " action(s).";
        return obj("schema", "atlas-pca/compliance-report/v1", "framework", framework, "generatedAt", Js.ts(now), "period", obj("from", Js.ts(from), "to", Js.ts(to)),
            "eventCount", st, "assurances", assurances, "items", items,
            "coverage", obj("total", total, "satisfied", satisfied, "partial", partial, "notEvidenced", notEvidenced, "satisfiedFraction", fraction,
                "satisfiedPercent", (long) Js.round(fraction * 100)),
            "summary", summary);
    }

    // ---- renderers ----

    /** The report as stable, pretty JSON ({@code JSON.stringify(report, null, 2)}). */
    public static String renderJson(Object report) { return Js.stringify(report, "", true); }

    private static String upper(Object v) {
        if (!(v instanceof String)) throw new IllegalStateException("toUpperCase is not a function");
        return ((String) v).toUpperCase(java.util.Locale.ROOT);
    }

    private static String glyph(Object status) {
        if ("satisfied".equals(status)) return "✓";
        if ("partial".equals(status)) return "◐";
        if ("not-evidenced".equals(status)) return "·";
        return "undefined";
    }

    private static Object walk(Object o, String... path) {
        for (String k : path) o = Js.prop(o, k);
        return o;
    }

    /** The report as an auditor-facing Markdown document (admissibility assurances, coverage, control table and detail). */
    @SuppressWarnings("unchecked")
    public static String renderMarkdown(Object r) {
        List<String> l = new ArrayList<>();
        l.add("# PCA compliance evidence — " + Js.tpl(walk(r, "framework")));
        l.add("");
        l.add("Generated " + Js.tpl(walk(r, "generatedAt", "iso")) + " · " + Js.tpl(walk(r, "eventCount")) + " action(s) · coverage: " + Js.tpl(walk(r, "coverage", "satisfied")) + "/"
            + Js.tpl(walk(r, "coverage", "total")) + " satisfied (" + Js.tpl(walk(r, "coverage", "satisfiedPercent")) + "%)");
        if (Js.gt(walk(r, "eventCount"), 0L)) {
            l.add("");
            l.add("Reporting period: " + Js.tpl(walk(r, "period", "from", "iso")) + " → " + Js.tpl(walk(r, "period", "to", "iso")));
        }
        l.add("");
        l.add("## Why this trail is admissible (what PCA uniquely provides)");
        l.add("");
        l.add("- **Cryptographically verifiable** — " + (Js.truthy(walk(r, "assurances", "cryptographicallyVerifiable")) ? "YES" : "PARTIAL")
            + ": every log entry cites its proof (the PCActn digest + the verifying leaf signature), so it is tamper-evident and cannot be back-dated.");
        l.add("- **Explicit delegation chain** — " + (Js.truthy(walk(r, "assurances", "explicitDelegationChain")) ? "YES" : "PARTIAL")
            + ": each action records who authorized what scope, hop by hop, rooted at a principal.");
        l.add("- **Signed human-overrides** — " + (Js.truthy(walk(r, "assurances", "signedHumanOverrides")) ? "YES" : "none in period")
            + ": a step-up approval is a principal threshold co-signature naming the human approver, not a free-text note.");
        l.add("");
        l.add("> " + Js.tpl(walk(r, "assurances", "narrative")));
        l.add("");
        l.add("## Coverage summary");
        l.add("");
        l.add("| Satisfied | Partial | Not evidenced | Total |");
        l.add("| --- | --- | --- | --- |");
        l.add("| " + Js.tpl(walk(r, "coverage", "satisfied")) + " | " + Js.tpl(walk(r, "coverage", "partial")) + " | " + Js.tpl(walk(r, "coverage", "notEvidenced")) + " | " + Js.tpl(walk(r, "coverage", "total")) + " |");
        l.add("");
        l.add("## Controls");
        l.add("");
        l.add("| Control | Clause | Status | Evidence in period |");
        l.add("| --- | --- | --- | --- |");
        Object items = walk(r, "items");
        if (!(items instanceof List)) throw new IllegalStateException("items is not iterable");
        for (Object i : (List<Object>) items) {
            l.add("| " + Js.tpl(Js.prop(i, "controlTitle")) + " (`" + Js.tpl(Js.prop(i, "controlId")) + "`) | " + Js.tpl(Js.prop(i, "clause")) + " | " + glyph(Js.prop(i, "status")) + " "
                + upper(Js.prop(i, "status")) + " | " + Js.tpl(Js.prop(i, "evidence")) + " |");
        }
        l.add("");
        l.add("## Control detail");
        l.add("");
        for (Object i : (List<Object>) items) {
            l.add("### " + Js.tpl(Js.prop(i, "controlId")) + " — " + Js.tpl(Js.prop(i, "controlTitle")));
            l.add("");
            l.add("- Clause: " + Js.tpl(Js.prop(i, "clause")));
            l.add("- Status: " + glyph(Js.prop(i, "status")) + " " + upper(Js.prop(i, "status")));
            l.add("- PCA evidence basis: " + Js.tpl(Js.prop(i, "pcaEvidence")));
            l.add("- Evidence in period: " + Js.tpl(Js.prop(i, "evidence")));
            Object n = Js.length(Js.prop(i, "findings"));
            if (n != UNDEF && (Long) n > 0) {
                l.add("- Findings:");
                Object fs = Js.prop(i, "findings");
                if (fs instanceof List) for (Object f : (List<Object>) fs) l.add("  - " + Js.tpl(f));
                else for (int k = 0; k < ((String) fs).length(); k++) l.add("  - " + ((String) fs).charAt(k)); // a string iterates by code point
            }
            l.add("");
        }
        l.add("---");
        l.add("");
        l.add("_Evidence mapping, not a legal certification: a `satisfied` status means the cryptographic evidence the control asks for is present in the supplied records._");
        return String.join("\n", l);
    }

    // ---- framework report (console activity stream) ----

    private static Object safetyBound(Object p) {
        Object kappa = Js.prop(p, "kappa"), bMax = Js.prop(p, "bMax");
        if (!Js.gt(kappa, 0L)) return 0.0;
        double b = Js.toNumber(bMax);
        return (Double.isNaN(b) ? Double.NaN : Math.max(0.0, b)) / Js.toNumber(kappa);
    }

    private static Map<String, Object> baseSummary(Object input) {
        Object ev = Js.prop(input, "events");
        if (!(ev instanceof List)) throw new IllegalStateException("e.filter is not a function");
        @SuppressWarnings("unchecked") List<Object> events = (List<Object>) ev;
        Object p = Js.prop(Js.prop(input, "policy"), "riskPolicy");
        Object decisions = Js.qprop(input, "decisions");
        Object dlen = Js.nullish(decisions) ? (Object) 0L : Js.length(decisions);
        double taint = 0;
        Js.JsSet agents = new Js.JsSet();
        long auto = 0, stepUp = 0, denied = 0;
        for (Object x : events) {
            Object t = Js.prop(x, "taint");
            double v = t == UNDEF ? 0 : Js.finite(t) ? Js.num(t) : Double.POSITIVE_INFINITY;
            taint = Math.max(taint, v);
        }
        for (Object x : events) agents.add(Js.prop(x, "agent"));
        for (Object x : events) { Object o = Js.prop(x, "outcome"); if ("auto".equals(o) || "executed".equals(o)) auto++; }
        for (Object x : events) if ("step_up".equals(Js.prop(x, "outcome"))) stepUp++;
        for (Object x : events) if ("deny".equals(Js.prop(x, "outcome"))) denied++;
        Object bound = safetyBound(p);
        double autonomous = ((Number) bound).doubleValue() * Js.toNumber(Js.prop(p, "kappa"));
        return obj("totalActions", (long) events.size(), "autonomous", auto, "humanOverseen", stepUp + (dlen == UNDEF ? 0 : (Long) dlen), "denied", denied,
            "attributableAgents", (long) agents.size(), "autonomousBound", autonomous, "maxTaintObserved", taint);
    }

    /** A number as the JSON value JavaScript would hold (integers as longs, infinities / NaN stay doubles for string rendering). */
    private static Object numVal(double d) { return d == Math.rint(d) && Math.abs(d) < 9e15 ? (Object) (long) d : (Object) d; }

    private static Map<String, Object> ctl(String id, String name, String status, String evidence) { return obj("id", id, "name", name, "status", status, "evidence", evidence); }

    private static String numS(Object v) {
        if (v instanceof Double) return Js.numStr((Double) v);
        return Js.tpl(v);
    }

    private static long lng(Object o) { return (Long) o; }

    private static List<Object> euAiAct(Object input, Map<String, Object> s) {
        boolean logged = lng(s.get("totalActions")) > 0;
        double bound = (Double) s.get("autonomousBound");
        boolean oversight = lng(s.get("humanOverseen")) > 0 || !Double.isNaN(bound) && !Double.isInfinite(bound);
        boolean goal = Js.truthy(Js.own(input, "hasGoalCommitment"));
        boolean fin = !Double.isNaN(bound) && !Double.isInfinite(bound);
        String b = Js.numStr(bound);
        return new ArrayList<>(List.of(
            ctl("art12-record-keeping", "Automatic logging of events", logged ? "pass" : "warn", s.get("totalActions") + " attributable actions recorded"),
            ctl("art14-human-oversight", "Human oversight", oversight ? "pass" : "warn", s.get("humanOverseen") + " human-reviewed actions; autonomous bound " + b),
            ctl("art15-robustness", "Bounded autonomy (accuracy/robustness)", fin ? "pass" : "fail", "machine-checked safety bound = " + b + " between human co-signs"),
            ctl("art13-transparency", "Transparency / traceability", goal ? "pass" : "warn", goal ? "every action binds to a signed goal commitment (lineage)" : "no goal commitment supplied")));
    }

    private static List<Object> soc2(Object input, Map<String, Object> s) {
        Object preds = Js.qprop(Js.own(input, "policy"), "predicates");
        boolean constrained = preds instanceof List && !((List<?>) preds).isEmpty();
        boolean any = lng(s.get("totalActions")) > 0;
        return new ArrayList<>(List.of(
            ctl("cc6.1-access", "Logical access — least privilege", constrained ? "pass" : "warn",
                constrained ? "actions constrained by signed predicates + capability attenuation (deny by default)" : "the supplied policy lists no predicates"),
            ctl("cc7.2-monitoring", "Monitoring of anomalies", any ? "pass" : "warn", s.get("denied") + " denied + " + s.get("humanOverseen") + " escalated actions captured"),
            ctl("cc7.3-audit-trail", "Audit trail", any ? "pass" : "warn", s.get("totalActions") + " content-addressed actions across " + s.get("attributableAgents") + " agents"),
            ctl("cc8.1-change", "Change management (policy integrity)", constrained ? "pass" : "warn",
                constrained ? "policy is signed into the grant; tampering breaks verification" : "the supplied policy lists no predicates")));
    }

    private static List<Object> gdpr(Object input, Map<String, Object> s) {
        boolean goal = Js.truthy(Js.own(input, "hasGoalCommitment"));
        boolean erasure = Js.truthy(Js.own(input, "erasureSupported"));
        return new ArrayList<>(List.of(
            ctl("art5-purpose", "Purpose limitation", goal ? "pass" : "warn", goal ? "actions bound to a committed goal/purpose" : "no goal commitment supplied"),
            ctl("art5-minimization", "Data minimisation", lng(s.get("totalActions")) > 0 ? "pass" : "warn", "taint-gated data flows; max taint observed = " + Js.numStr((Double) s.get("maxTaintObserved"))),
            ctl("art5-accountability", "Accountability", lng(s.get("attributableAgents")) > 0 ? "pass" : "warn", s.get("attributableAgents") + " attributable agent identities"),
            ctl("art17-erasure", "Right to erasure", erasure ? "pass" : "warn", erasure ? "erasure path wired" : "erasure path not asserted")));
    }

    /** A compliance evidence report for a framework from the console activity stream; {@code now} defaults to the clock when UNDEF-like null args are absent. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> frameworkReport(Object framework, Object input, Object now) {
        Map<String, Object> summary = baseSummary(input);
        if (!(framework instanceof String) || !FRAMEWORK_IDS.contains(framework)) {
            throw new IllegalArgumentException("frameworkReport: unknown framework '" + Js.tpl(framework) + "' (have: " + String.join(", ", FRAMEWORK_IDS) + ")");
        }
        List<Object> controls = framework.equals("eu-ai-act") ? euAiAct(input, summary) : framework.equals("soc2") ? soc2(input, summary) : gdpr(input, summary);
        List<Object> events = (List<Object>) Js.prop(input, "events");
        List<Double> ats = new ArrayList<>();
        for (Object e : events) { Object a = Js.prop(e, "at"); if (Js.finite(a)) ats.add(Js.num(a)); }
        double lo = 0, hi = 0;
        if (!ats.isEmpty()) { lo = hi = ats.get(0); for (double d : ats) { lo = Math.min(lo, d); hi = Math.max(hi, d); } }
        boolean pass = true;
        for (Object c : controls) if ("fail".equals(((Map<String, Object>) c).get("status"))) pass = false;
        // the bound and taint stay the numbers the reference holds (possibly Infinity / NaN); only a serializer drops those to null
        return obj("framework", framework, "generatedAt", now == UNDEF ? Js.nowMs() : now, "period", obj("from", jsonNum(lo), "to", jsonNum(hi)), "summary", summary, "controls", controls, "pass", pass);
    }

    public static Map<String, Object> frameworkReport(Object framework, Object input) { return frameworkReport(framework, input, UNDEF); }

    private static Object jsonNum(double d) { return Double.isNaN(d) || Double.isInfinite(d) ? null : numVal(d); }

    private static String dateIso(Object v) {
        Object x = v instanceof Boolean ? (Object) ((Boolean) v ? 1L : 0L) : v;
        if (!Js.isNum(x) && x != null) throw new IllegalArgumentException("Invalid time value");
        return Js.isoString(x);
    }

    /** A short Markdown block of a framework report, for an audit package. */
    @SuppressWarnings("unchecked")
    public static String frameworkReportToMarkdown(Object r) {
        Object summary = Js.prop(r, "summary");
        Object controls = Js.prop(r, "controls");
        if (!(controls instanceof List)) throw new IllegalStateException("r.controls.map is not a function");
        List<String> l = new ArrayList<>(Arrays.asList(
            "# PCA compliance evidence — " + Js.tpl(Js.prop(r, "framework")), "",
            "Generated " + dateIso(Js.prop(r, "generatedAt")) + " · " + Js.tpl(Js.prop(summary, "totalActions")) + " actions · " + Js.tpl(Js.prop(summary, "attributableAgents"))
                + " agents · overall: " + (Js.truthy(Js.prop(r, "pass")) ? "PASS" : "FAIL"),
            "", "| Control | Status | Evidence |", "| --- | --- | --- |"));
        for (Object c : (List<Object>) controls) {
            l.add("| " + Js.tpl(Js.prop(c, "name")) + " (" + Js.tpl(Js.prop(c, "id")) + ") | " + upper(Js.prop(c, "status")) + " | " + Js.tpl(Js.prop(c, "evidence")) + " |");
        }
        l.add("");
        l.add("_Evidence mapping, not a legal certification._");
        return String.join("\n", l);
    }
}
