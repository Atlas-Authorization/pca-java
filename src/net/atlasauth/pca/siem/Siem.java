package net.atlasauth.pca.siem;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoField;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.revoke.JsVal;

/**
 * A SIEM export for PCA authorization decisions: every verify / deny becomes a security event in OCSF, ArcSight CEF or Elastic
 * Common Schema, citing the cryptographic proof digest and the full delegation chain. Everything is pure and read-only over
 * the decision record (a JSON tree: {@code pcactn}, {@code verify}, {@code decision}, {@code now}, {@code session}), and
 * mirrors the TypeScript exports of the same name. Shipping never throws into the caller's authorization path.
 */
public final class Siem {
    private Siem() {}

    /** A JavaScript {@code undefined}: an absent member (JSON null stays Java null). */
    private static final Object UNDEF = new Object();

    // ---- severity ---------------------------------------------------------------------------------------------------------------------

    private static final class Severity {
        final int id; final String name; final int cef;
        Severity(int id, String name, int cef) { this.id = id; this.name = name; this.cef = cef; }
    }

    private static final Severity SEV_INFO = new Severity(1, "Informational", 1);
    private static final Severity SEV_LOW = new Severity(2, "Low", 3);
    private static final Severity SEV_MEDIUM = new Severity(3, "Medium", 5);
    private static final Severity SEV_HIGH = new Severity(4, "High", 8);

    /** Normative checks whose failure means a real security event (tamper / forged authority), not a policy veto. */
    private static final String[] SECURITY_CHECKS = {"wire", "version", "audience", "validity", "cap_chain", "plan_inclusion", "leaf_signature", "counter_format", "replay"};

    // ---- JavaScript-flavoured reads ---------------------------------------------------------------------------------------------------

    /** {@code o?.[k]}: UNDEF for a non-object or an absent member, JSON null when the member is null. */
    private static Object g(Object o, String k) {
        if (o instanceof Map) { Map<?, ?> m = (Map<?, ?>) o; return m.containsKey(k) ? m.get(k) : UNDEF; }
        return UNDEF;
    }

    /** JavaScript truthiness; an undefined member is falsy. */
    private static boolean tr(Object v) { return v != UNDEF && JsVal.truthy(v); }

    private static boolean nullish(Object v) { return v == null || v == UNDEF; }

    private static String str(Object v, String fallback) { return v instanceof String && !((String) v).isEmpty() ? (String) v : fallback; }

    private static Double finiteNum(Object v) {
        if (v == UNDEF) return null;
        Double d = JsVal.num(v);
        return d != null && !d.isNaN() && !d.isInfinite() ? d : null;
    }

    /** Abbreviate a long b64u key for display in narratives / CEF names. */
    private static String shortKey(Object key) {
        if (!(key instanceof String) || ((String) key).isEmpty()) return "(none)";
        String k = (String) key;
        return k.length() <= 13 ? k : k.substring(0, 12) + "…";
    }

    private static Json.Num numJ(double d) { return new Json.Num(d == 0.0 && Double.doubleToRawLongBits(d) != 0L ? "-0" : JsFmt.num(d)); }

    private static Json.Num intJ(long v) { return new Json.Num(Long.toString(v)); }

    private static void put(Map<String, Object> m, String k, Object v) { if (v != UNDEF) m.put(k, v); }

    private static void putOpt(Map<String, Object> m, String k, Object v) { if (v != null && v != UNDEF) m.put(k, v); }

    private static Map<String, Object> map() { return new LinkedHashMap<>(); }

    // ---- normalization ----------------------------------------------------------------------------------------------------------------

    private static final class Hop {
        int index; boolean isRoot; String issuer; String holder; int addedCaveats;
        Map<String, Object> asChain() {
            Map<String, Object> m = map();
            m.put("index", intJ(index)); m.put("is_root", isRoot); m.put("issuer", issuer); m.put("holder", holder); m.put("added_caveats", intJ(addedCaveats));
            return m;
        }
        Map<String, Object> asView() {
            Map<String, Object> m = map();
            m.put("index", intJ(index)); m.put("isRoot", isRoot); m.put("issuer", issuer); m.put("holder", holder); m.put("addedCaveats", intJ(addedCaveats));
            return m;
        }
    }

    private static final class Normalized {
        double now;
        String outcome, reason;
        boolean cryptographicallyVerifiable;
        Object checks;
        String agentHolder;
        String principal;
        String session;
        List<Hop> hops;
        int depth;
        String chainString, verb, resource, paramsDigest, reversibilityClass, grantRef;
        double counter;
        String nonce, planRoot, signatureSuite, leafSignature, proofDigest;
        Double riskScore;
        Object tier = UNDEF;
        Object proofStrength = UNDEF;
        Double caution;
        String bondRef;
        boolean humanApproved;
        List<Object> approvers = new ArrayList<>(), guardianCosigners = new ArrayList<>(), roles = new ArrayList<>();
        Severity severity;
        double iat, exp;
    }

    private static String safeDigest(Object p) {
        if (p == UNDEF) return "(undigestible)";
        try { return Pca.hashCanonical(p); } catch (RuntimeException | StackOverflowError e) { return "(undigestible)"; }
    }

    private static String firstReasonOr(Object decision, String fallback) {
        Object rs = g(decision, "reasons");
        if (rs instanceof List && !((List<?>) rs).isEmpty()) {
            Object first = ((List<?>) rs).get(0);
            if (first instanceof String && !((String) first).isEmpty()) return (String) first;
        }
        return fallback;
    }

    /** Returns {outcome, reason}. */
    private static String[] resolveOutcome(Object verify, Object decision) {
        if (!tr(verify) || !Boolean.TRUE.equals(g(verify, "allow"))) {
            return new String[] {"deny", str(g(verify, "reason"), "proof failed verification")};
        }
        if (!tr(decision)) return new String[] {"allow", "proof verified; no policy decision supplied"};
        if (tr(g(decision, "admit"))) return new String[] {"allow", firstReasonOr(decision, "auto-admitted within policy and budget")};
        if (tr(g(decision, "releaseGuardianShare"))) return new String[] {"step-up", firstReasonOr(decision, "policy satisfied but a co-signature is required")};
        return new String[] {"deny", firstReasonOr(decision, "policy did not release authority (default-deny)")};
    }

    private static List<Hop> buildHops(List<?> chain) {
        List<Hop> hops = new ArrayList<>();
        for (int i = 0; i < chain.size(); i++) {
            Object cap = chain.get(i);
            if (!tr(cap)) continue;
            Object parent = i > 0 ? chain.get(i - 1) : null;
            int parentLen = tr(parent) && g(parent, "caveats") instanceof List ? ((List<?>) g(parent, "caveats")).size() : 0;
            Object oc = g(cap, "caveats");
            int ownLen = oc instanceof List ? ((List<?>) oc).size() : 0;
            Hop h = new Hop();
            h.index = i; h.isRoot = i == 0;
            h.issuer = str(g(cap, "issuer"), "(none)"); h.holder = str(g(cap, "holder"), "(none)");
            h.addedCaveats = i == 0 ? ownLen : Math.max(0, ownLen - parentLen);
            hops.add(h);
        }
        return hops;
    }

    private static void readOverride(Normalized n, Object threshold, Object thresholdCheck) {
        Object shares = tr(threshold) ? g(threshold, "shares") : UNDEF;
        List<?> list = shares instanceof List ? (List<?>) shares : new ArrayList<>();
        // `threshold` sits outside the signed body: its shares prove nothing until a threshold verifier passed.
        if (!"pass".equals(thresholdCheck)) return;
        for (Object s : list) {
            if (!tr(s) || !(g(s, "role") instanceof String)) continue;
            String role = (String) g(s, "role");
            n.roles.add(role);
            Object pk = g(s, "publicKey");
            if (role.equals("principal") && pk instanceof String) n.approvers.add(pk);
            if (role.equals("guardian") && pk instanceof String) n.guardianCosigners.add(pk);
        }
        n.humanApproved = !n.approvers.isEmpty();
    }

    private static boolean isNumber(Object v, double want) { Double d = v == UNDEF ? null : JsVal.num(v); return d != null && d == want; }

    private static Severity severityFor(String outcome, Object checks, Object tier) {
        if (outcome.equals("deny")) {
            boolean securityFailure = false;
            for (String k : SECURITY_CHECKS) if ("fail".equals(g(checks, k))) securityFailure = true;
            return securityFailure ? SEV_HIGH : SEV_MEDIUM;
        }
        if (outcome.equals("step-up")) return SEV_MEDIUM;
        return isNumber(tier, 3) ? SEV_MEDIUM : isNumber(tier, 2) ? SEV_LOW : SEV_INFO;
    }

    private static String shownSignature(String sig, Object mode) {
        if ("full".equals(mode)) return sig;
        if ("omit".equals(mode)) return "(omitted)";
        return sig.length() <= 16 ? sig : sig.substring(0, 16) + "…";
    }

    /** One total pass: extract everything the exporters need. Never throws; degrades to best-effort values. */
    private static Normalized normalize(Object record, Object opts) {
        Object p = g(record, "pcactn");
        Object vraw = g(record, "verify");
        Object verify = nullish(vraw) ? null : vraw;
        Object checksRaw = verify == null ? UNDEF : g(verify, "checks");
        Object checks = nullish(checksRaw) ? map() : checksRaw;
        Double nowD = finiteNum(g(record, "now"));
        double now = nowD != null ? nowD : (double) System.currentTimeMillis();
        Object chainRaw = g(p, "cap_chain");
        List<?> chain = chainRaw instanceof List ? (List<?>) chainRaw : new ArrayList<>();
        List<Hop> hops = buildHops(chain);
        Object leaf = chain.isEmpty() ? UNDEF : chain.get(chain.size() - 1);
        Object root = chain.isEmpty() ? UNDEF : chain.get(0);

        Object decision = g(record, "decision");
        String[] or = resolveOutcome(vraw == UNDEF ? null : vraw, decision == UNDEF ? null : decision); // an absent member is falsy
        Normalized n = new Normalized();
        n.outcome = or[0]; n.reason = or[1];
        Object rt = g(g(decision, "requiredThreshold"), "t");
        readOverride(n, g(p, "threshold"), g(checks, "threshold"));

        String grantRef = str(g(p, "grant_ref"), "(none)");
        Object rootIssuer = g(root, "issuer");
        n.principal = rootIssuer instanceof String && !((String) rootIssuer).isEmpty() ? (String) rootIssuer : null;
        n.agentHolder = str(g(leaf, "holder"), "(none)");
        List<String> parts = new ArrayList<>();
        parts.add(shortKey(n.principal != null ? n.principal : "(principal?)"));
        for (Hop h : hops) parts.add(shortKey(h.holder));

        n.now = now;
        n.cryptographicallyVerifiable = "pass".equals(g(checks, "wire")) && "pass".equals(g(checks, "leaf_signature"));
        n.checks = checks;
        n.session = str(g(record, "session"), grantRef);
        n.hops = hops;
        n.depth = hops.size() > 0 ? hops.size() - 1 : 0;
        n.chainString = String.join(" -> ", parts);
        Object action = g(p, "action");
        n.verb = str(g(action, "verb"), "(unknown verb)");
        n.resource = str(g(action, "resource"), "(unknown resource)");
        n.paramsDigest = str(g(action, "params_digest"), "(none)");
        n.reversibilityClass = str(g(action, "reversibility_class"), "(unknown)");
        n.grantRef = grantRef;
        Double counter = finiteNum(g(p, "counter"));
        n.counter = counter != null ? counter : -1.0;
        n.nonce = g(p, "nonce") instanceof String ? (String) g(p, "nonce") : null;
        n.planRoot = str(g(g(p, "plan"), "root"), "(none)");
        n.signatureSuite = str(g(p, "alg"), "ed25519");
        n.leafSignature = shownSignature(str(g(p, "sig"), "(unsigned)"), g(opts, "signature"));
        n.proofDigest = safeDigest(p);
        n.riskScore = finiteNum(g(decision, "r"));
        n.tier = rt;
        n.proofStrength = g(g(decision, "requiredThreshold"), "proof");
        n.caution = finiteNum(g(p, "caution"));
        n.bondRef = g(p, "bond_ref") instanceof String ? (String) g(p, "bond_ref") : null;
        n.severity = severityFor(n.outcome, checks, rt);
        Double iat = finiteNum(g(p, "iat"));
        n.iat = iat != null ? iat : now;
        Double exp = finiteNum(g(p, "exp"));
        n.exp = exp != null ? exp : now;
        return n;
    }

    private static Map<String, Object> humanOverride(Normalized n) {
        Map<String, Object> m = map();
        m.put("human_approved", true);
        m.put("approvers", new ArrayList<>(n.approvers));
        m.put("guardian_cosigners", new ArrayList<>(n.guardianCosigners));
        m.put("roles", new ArrayList<>(n.roles));
        return m;
    }

    private static List<Object> chainJson(Normalized n) {
        List<Object> out = new ArrayList<>();
        for (Hop h : n.hops) out.add(h.asChain());
        return out;
    }

    /** The PCA-specific block every schema carries verbatim (the cryptographic edge). */
    private static Map<String, Object> pcaExtensions(Normalized n) {
        Map<String, Object> m = map();
        m.put("proof_digest", n.proofDigest);
        m.put("leaf_signature", n.leafSignature);
        m.put("signature_suite", n.signatureSuite);
        m.put("cryptographically_verifiable", n.cryptographicallyVerifiable);
        m.put("plan_root", n.planRoot);
        m.put("params_digest", n.paramsDigest);
        m.put("grant_ref", n.grantRef);
        m.put("counter", numJ(n.counter));
        putOpt(m, "nonce", n.nonce);
        m.put("reversibility_class", n.reversibilityClass);
        if (n.riskScore != null) m.put("risk_score", numJ(n.riskScore));
        put(m, "risk_tier", n.tier);
        put(m, "required_proof", n.proofStrength);
        if (n.caution != null) m.put("caution", numJ(n.caution));
        putOpt(m, "bond_ref", n.bondRef);
        m.put("delegation_depth", intJ(n.depth));
        m.put("delegation_chain", chainJson(n));
        m.put("checks", n.checks);
        if (n.humanApproved) m.put("human_override", humanOverride(n));
        return m;
    }

    // ---- OCSF -------------------------------------------------------------------------------------------------------------------------

    private static final int OCSF_CLASS_UID = 3003;
    private static final String OCSF_SCHEMA_VERSION = "1.1.0";

    private static Map<String, Object> user(int typeId, String type, String uid, String name) {
        Map<String, Object> m = map();
        m.put("type_id", intJ(typeId)); m.put("type", type); m.put("uid", uid); m.put("name", name);
        return m;
    }

    private static Map<String, Object> observable(String name, String type, int typeId, String value) {
        Map<String, Object> m = map();
        m.put("name", name); m.put("type", type); m.put("type_id", intJ(typeId)); m.put("value", value);
        return m;
    }

    /** Map a PCA decision to an OCSF 1.x Authorize Session event (Identity and Access Management, class 3003). */
    public static Map<String, Object> toOcsfEvent(Object record, Map<String, Object> opts) {
        Normalized n = normalize(record, opts);
        int activityId; String activityName; int actionId; String actionName;
        int statusId; String statusName; String statusDetail;
        switch (n.outcome) {
            case "allow": activityId = 1; activityName = "Allow"; actionId = 1; actionName = "Allowed"; statusId = 1; statusName = "Success"; statusDetail = n.reason; break;
            case "deny": activityId = 2; activityName = "Deny"; actionId = 2; actionName = "Denied"; statusId = 2; statusName = "Failure"; statusDetail = n.reason; break;
            default: activityId = 3; activityName = "Step-Up"; actionId = 99; actionName = "Other"; statusId = 99; statusName = "Other"; statusDetail = "step-up / co-signature required: " + n.reason;
        }
        String className = "Authorize Session";
        Map<String, Object> e = map();
        e.put("activity_id", intJ(activityId));
        e.put("activity_name", activityName);
        e.put("category_uid", intJ(3));
        e.put("category_name", "Identity & Access Management");
        e.put("class_uid", intJ(OCSF_CLASS_UID));
        e.put("class_name", className);
        e.put("type_uid", intJ(OCSF_CLASS_UID * 100L + activityId));
        e.put("type_name", className + ": " + activityName);
        e.put("action_id", intJ(actionId));
        e.put("action", actionName);
        e.put("severity_id", intJ(n.severity.id));
        e.put("severity", n.severity.name);
        e.put("status_id", intJ(statusId));
        e.put("status", statusName);
        e.put("status_detail", statusDetail);
        e.put("time", numJ(n.iat));
        Map<String, Object> actor = map();
        actor.put("user", user(99, "Agent", n.agentHolder, shortKey(n.agentHolder)));
        actor.put("invoked_by", n.principal != null ? n.principal : "(none)");
        Map<String, Object> session = map();
        session.put("uid", n.session);
        putOpt(session, "issuer", n.principal);
        actor.put("session", session);
        actor.put("app_name", "PCA");
        e.put("actor", actor);
        e.put("user", user(1, "User", n.principal != null ? n.principal : "(none)", shortKey(n.principal)));
        Map<String, Object> res = map();
        res.put("type", "pca.resource"); res.put("name", n.resource); res.put("uid", n.resource);
        List<Object> resources = new ArrayList<>();
        resources.add(res);
        e.put("resources", resources);
        Map<String, Object> api = map();
        api.put("operation", n.verb);
        Map<String, Object> svc = map();
        svc.put("name", "PCA");
        api.put("service", svc);
        e.put("api", api);
        Map<String, Object> md = map();
        md.put("version", OCSF_SCHEMA_VERSION);
        Map<String, Object> product = map();
        product.put("name", "PCA"); product.put("vendor_name", "Atlas"); product.put("version", OCSF_SCHEMA_VERSION);
        md.put("product", product);
        md.put("logged_time", numJ(n.now));
        md.put("uid", n.proofDigest);
        List<Object> labels = new ArrayList<>();
        labels.add("pca"); labels.add("outcome:" + n.outcome); labels.add("suite:" + n.signatureSuite);
        md.put("labels", labels);
        e.put("metadata", md);
        List<Object> obs = new ArrayList<>();
        obs.add(observable("actor.user.uid", "User Name", 4, n.agentHolder));
        obs.add(observable("pca.proof.digest", "Hash", 8, n.proofDigest));
        obs.add(observable("resources.uid", "Resource UID", 10, n.resource));
        e.put("observables", obs);
        e.put("count", intJ(1));
        e.put("message", narrative(n));
        e.put("unmapped", pcaExtensions(n));
        return e;
    }

    // ---- CEF --------------------------------------------------------------------------------------------------------------------------

    /** Escape a CEF header field: backslash and pipe are reserved. */
    private static String cefHeaderEscape(String s) {
        return s.replace("\\", "\\\\").replace("|", "\\|").replaceAll("[\\r\\n]+", " ");
    }

    /** Escape a CEF extension value: backslash, equals and newlines are reserved. */
    private static String cefExtValueEscape(String s) {
        return s.replace("\\", "\\\\").replace("=", "\\=").replaceAll("\\r\\n|\\r|\\n", "\\\\n");
    }

    private static void ext(List<String> out, String k, String v) { out.add(k + "=" + cefExtValueEscape(v)); }

    /** Entries of {@code Object.entries(v)} rendered {@code key:value} (an object, an array or the characters of a string). */
    private static List<String> checkPairs(Object v) {
        List<String> out = new ArrayList<>();
        if (v instanceof Map) {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) out.add(e.getKey() + ":" + JsFmt.str(e.getValue()));
        } else if (v instanceof List) {
            List<?> xs = (List<?>) v;
            for (int i = 0; i < xs.size(); i++) out.add(i + ":" + (xs.get(i) == null ? "null" : JsFmt.str(xs.get(i))));
        } else if (v instanceof String) {
            String s = (String) v;
            for (int i = 0; i < s.length(); i++) out.add(i + ":" + s.charAt(i));
        }
        return out;
    }

    /**
     * Map a PCA decision to a single ArcSight CEF line: {@code CEF:0|Atlas|PCA|<wireVer>|pca-authz-<outcome>|<name>|<sev>|ext...}, with the
     * proof digest, the delegation chain, the risk tier and proof strength as custom fields.
     */
    public static String toCef(Object record, Map<String, Object> opts) {
        Normalized n = normalize(record, opts);
        Double wireVer = finiteNum(g(g(record, "pcactn"), "ver"));
        String deviceVersion = wireVer != null ? JsFmt.num(wireVer) : "2";
        String signatureId = "pca-authz-" + n.outcome;
        String name = "PCA authorization " + n.outcome + ": " + n.verb + " on " + n.resource;
        String header = String.join("|", "CEF:0", cefHeaderEscape("Atlas"), cefHeaderEscape("PCA"), cefHeaderEscape(deviceVersion),
            cefHeaderEscape(signatureId), cefHeaderEscape(name), Integer.toString(n.severity.cef));
        String principal = n.principal != null ? n.principal : "(none)";
        List<String> x = new ArrayList<>();
        ext(x, "act", n.outcome);
        ext(x, "outcome", n.outcome);
        ext(x, "suser", principal);
        ext(x, "suid", principal);
        ext(x, "duser", n.agentHolder);
        ext(x, "duid", n.agentHolder);
        ext(x, "destinationServiceName", n.verb);
        ext(x, "rt", JsFmt.num(n.now));
        ext(x, "start", JsFmt.num(n.iat));
        ext(x, "end", JsFmt.num(n.exp));
        ext(x, "externalId", n.nonce != null ? n.nonce : JsFmt.num(n.counter));
        ext(x, "request", n.resource);
        ext(x, "requestMethod", n.verb);
        ext(x, "cs1Label", "pcaProofDigest");
        ext(x, "cs1", n.proofDigest);
        ext(x, "cs2Label", "pcaDelegationChain");
        ext(x, "cs2", n.chainString);
        ext(x, "cs3Label", "pcaProofStrength");
        ext(x, "cs3", nullish(n.proofStrength) ? "n/a" : JsFmt.str(n.proofStrength));
        ext(x, "cs4Label", "pcaSignatureSuite");
        ext(x, "cs4", n.signatureSuite);
        ext(x, "cs5Label", "pcaVerifyChecks");
        ext(x, "cs5", String.join(";", checkPairs(n.checks)));
        ext(x, "cs6Label", "pcaGrantRef");
        ext(x, "cs6", n.grantRef);
        ext(x, "cn1Label", "pcaRiskScore");
        ext(x, "cn1", n.riskScore != null ? JsFmt.num(n.riskScore) : "");
        ext(x, "cn2Label", "pcaDelegationDepth");
        ext(x, "cn2", Integer.toString(n.depth));
        ext(x, "cn3Label", "pcaRiskTier");
        ext(x, "cn3", nullish(n.tier) ? "" : JsFmt.str(n.tier));
        ext(x, "flexString1Label", "pcaHumanApproved");
        ext(x, "flexString1", n.humanApproved ? "true" : "false");
        ext(x, "cat", "authorization");
        ext(x, "msg", n.reason);
        return header + "|" + String.join(" ", x);
    }

    // ---- ECS --------------------------------------------------------------------------------------------------------------------------

    private static final String ECS_VERSION = "8.11.0";

    private static List<Object> dedupe(List<Object> in) {
        List<Object> out = new ArrayList<>();
        for (Object v : in) if (!out.contains(v)) out.add(v);
        return out;
    }

    /** Map a PCA decision to an Elastic Common Schema event (category iam; the PCA edge under {@code pca.*}). */
    public static Map<String, Object> toEcs(Object record, Map<String, Object> opts) {
        Normalized n = normalize(record, opts);
        List<Object> users = new ArrayList<>();
        users.add(n.agentHolder);
        if (n.principal != null && !n.principal.isEmpty()) users.add(n.principal);
        users.addAll(n.approvers);
        List<Object> hashes = new ArrayList<>();
        hashes.add(n.proofDigest); hashes.add(n.leafSignature);

        String type = n.outcome.equals("allow") ? "allowed" : n.outcome.equals("deny") ? "denied" : "info";
        String outcome = n.outcome.equals("allow") ? "success" : n.outcome.equals("deny") ? "failure" : "unknown";
        Map<String, Object> event = map();
        event.put("kind", "event");
        List<Object> cat = new ArrayList<>(); cat.add("iam");
        event.put("category", cat);
        List<Object> types = new ArrayList<>(); types.add(type);
        event.put("type", types);
        event.put("action", n.verb);
        event.put("outcome", outcome);
        event.put("module", "pca");
        event.put("dataset", "pca.authorization");
        event.put("provider", "pca");
        event.put("id", n.proofDigest);
        event.put("severity", intJ(n.severity.cef));
        event.put("reason", n.reason);
        if (n.riskScore != null) event.put("risk_score", numJ(n.riskScore));

        Map<String, Object> e = map();
        e.put("@timestamp", isoOf(n.iat));
        e.put("ecs.version", ECS_VERSION);
        e.put("event", event);
        Map<String, Object> user = map();
        user.put("id", n.agentHolder);
        user.put("name", shortKey(n.agentHolder));
        List<Object> roles = new ArrayList<>(); roles.add("agent");
        user.put("roles", roles);
        Map<String, Object> eff = map();
        eff.put("id", n.principal != null ? n.principal : "(none)");
        eff.put("name", shortKey(n.principal));
        user.put("effective", eff);
        e.put("user", user);
        Map<String, Object> service = map();
        service.put("name", "pca"); service.put("type", "authorization");
        e.put("service", service);
        Map<String, Object> related = map();
        related.put("user", dedupe(users));
        related.put("hash", dedupe(hashes));
        e.put("related", related);
        e.put("message", narrative(n));

        Map<String, Object> pca = map();
        pca.put("outcome", n.outcome);
        Map<String, Object> proof = map();
        proof.put("digest", n.proofDigest);
        proof.put("leaf_signature", n.leafSignature);
        proof.put("signature_suite", n.signatureSuite);
        proof.put("cryptographically_verifiable", n.cryptographicallyVerifiable);
        proof.put("plan_root", n.planRoot);
        proof.put("params_digest", n.paramsDigest);
        pca.put("proof", proof);
        Map<String, Object> risk = map();
        if (n.riskScore != null) risk.put("score", numJ(n.riskScore));
        put(risk, "tier", n.tier);
        put(risk, "required_proof", n.proofStrength);
        if (n.caution != null) risk.put("caution", numJ(n.caution));
        pca.put("risk", risk);
        Map<String, Object> delegation = map();
        delegation.put("depth", intJ(n.depth));
        delegation.put("chain", n.chainString);
        List<Object> hops = new ArrayList<>();
        for (Hop h : n.hops) hops.add(h.asView());
        delegation.put("hops", hops);
        pca.put("delegation", delegation);
        pca.put("grant_ref", n.grantRef);
        pca.put("counter", numJ(n.counter));
        putOpt(pca, "nonce", n.nonce);
        pca.put("reversibility_class", n.reversibilityClass);
        putOpt(pca, "bond_ref", n.bondRef);
        pca.put("checks", n.checks);
        if (n.humanApproved) pca.put("human_override", humanOverride(n));
        e.put("pca", pca);
        return e;
    }

    private static final String EPOCH_ISO = "1970-01-01T00:00:00.000Z";

    /** {@code new Date(ms).toISOString()}, or the epoch for a time outside the Date range. */
    static String isoOf(double ms) {
        if (Double.isNaN(ms) || Double.isInfinite(ms)) return EPOCH_ISO;
        double t = ms < 0 ? Math.ceil(ms) : Math.floor(ms);
        if (Math.abs(t) > 8.64e15) return EPOCH_ISO;
        ZonedDateTime z = Instant.ofEpochMilli((long) t).atZone(ZoneOffset.UTC);
        int y = z.getYear();
        String year = y >= 0 && y <= 9999 ? String.format(Locale.ROOT, "%04d", y) : (y < 0 ? "-" : "+") + String.format(Locale.ROOT, "%06d", Math.abs(y));
        return String.format(Locale.ROOT, "%s-%02d-%02dT%02d:%02d:%02d.%03dZ", year, z.getMonthValue(), z.getDayOfMonth(), z.getHour(), z.getMinute(), z.getSecond(), z.get(ChronoField.MILLI_OF_SECOND));
    }

    /** One-sentence plain-English narration of the whole event (shared across schemas). */
    private static String narrative(Normalized n) {
        String word = n.outcome.equals("allow") ? "ALLOWED" : n.outcome.equals("deny") ? "DENIED" : "STEP-UP";
        return "Agent " + shortKey(n.agentHolder) + " " + word + " to " + n.verb + " on " + n.resource + " ("
            + n.hops.size() + "-hop chain rooted at principal " + shortKey(n.principal) + "; "
            + (n.cryptographicallyVerifiable ? "cryptographically verifiable proof" : "proof not cryptographically verifiable")
            + (n.humanApproved ? "; human-signed step-up" : "") + "). " + n.reason;
    }

    // ---- sinks ------------------------------------------------------------------------------------------------------------------------

    /** A single serialized event ready to ship: the structured object (OCSF / ECS; null for CEF) plus a one-line payload. */
    public static final class SiemEvent {
        public final String format;
        public final Map<String, Object> object;
        public final String line;
        public SiemEvent(String format, Map<String, Object> object, String line) { this.format = format; this.object = object; this.line = line; }
        public Map<String, Object> toMap() {
            Map<String, Object> m = map();
            m.put("format", format);
            if (object != null) m.put("object", object);
            m.put("line", line);
            return m;
        }
    }

    public static final class SinkResult {
        public final boolean ok;
        public final String error;
        public SinkResult(boolean ok, String error) { this.ok = ok; this.error = error; }
        public static SinkResult success() { return new SinkResult(true, null); }
        public static SinkResult failure(String error) { return new SinkResult(false, error); }
        public Map<String, Object> toMap() {
            Map<String, Object> m = map();
            m.put("ok", ok);
            if (error != null) m.put("error", error);
            return m;
        }
    }

    /** A pluggable SIEM destination; {@code deliver} should not throw and must not block the caller's authorization path. */
    public interface SiemSink {
        String name();
        String format();
        SinkResult deliver(List<SiemEvent> events) throws Exception;
    }

    /** Serialize a decision record into the given schema ("ocsf", "cef" or "ecs"; anything but cef / ocsf is ECS). */
    public static SiemEvent formatDecision(Object record, String format, Map<String, Object> opts) {
        if ("cef".equals(format)) return new SiemEvent(format, null, toCef(record, opts));
        Map<String, Object> object = "ocsf".equals(format) ? toOcsfEvent(record, opts) : toEcs(record, opts);
        return new SiemEvent(format, object, JsFmt.stringify(object));
    }

    private static String contentType(String format) {
        if ("ocsf".equals(format) || "ecs".equals(format)) return "application/x-ndjson";
        if ("cef".equals(format)) return "text/plain; charset=utf-8";
        return null;
    }

    // JavaScript whitespace (what \s matches), spelled out because the Java \s is ASCII only.
    private static final String WS = " \\t\\n\\u000B\\f\\r\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff";
    // \b before a word character, spelled out because the Java \b is Unicode-aware.
    private static final String WB = "(?<![A-Za-z0-9_])";
    private static final Pattern URL_USERINFO = Pattern.compile("([a-z][a-z0-9+.-]*:\\/\\/)[^" + WS + "/@]*:[^" + WS + "/@]*@", Pattern.CASE_INSENSITIVE);
    private static final Pattern AUTH_HEADER = Pattern.compile(WB + "(authorization[\"']?[" + WS + "]*[:=][" + WS + "]*)[^\\n\"']*", Pattern.CASE_INSENSITIVE);
    private static final Pattern SCHEME = Pattern.compile(WB + "(Bearer|Basic|Splunk|Token)[" + WS + "]+[\\w.~+/=-]{6,}", Pattern.CASE_INSENSITIVE);
    private static final Pattern KEYED = Pattern.compile(WB + "((?:token|secret|password|passwd|pwd|api[_-]?key|dd-api-key|key|signature|sig|credential)[\"']?[" + WS + "]*[:=][" + WS + "]*)(\"[^\"]*\"|'[^']*'|[^" + WS + "\"'&,;]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern LONG_RUN = Pattern.compile("[A-Za-z0-9_-]{32,}");

    /**
     * Remove credentials from an error message before it is returned or handed to {@code onError}: URL userinfo, token / key style pairs,
     * bearer credentials and long token-like runs; at most 300 characters.
     */
    public static String scrubError(String message) {
        String t = message == null ? "null" : message;
        t = URL_USERINFO.matcher(t).replaceAll("$1[redacted]@");
        t = AUTH_HEADER.matcher(t).replaceAll("$1[redacted]");
        t = SCHEME.matcher(t).replaceAll("$1 [redacted]");
        t = KEYED.matcher(t).replaceAll("$1[redacted]");
        t = LONG_RUN.matcher(t).replaceAll("[redacted]");
        return t.length() > 300 ? t.substring(0, 300) + "..." : t;
    }

    private static String messageOf(Throwable e) { return e.getMessage() != null ? e.getMessage() : e.toString(); }

    /** The minimal shape of a fetch response this package reads. */
    public static final class FetchLikeResponse {
        public final boolean ok;
        public final int status;
        public final String statusText;
        public FetchLikeResponse(boolean ok, int status, String statusText) { this.ok = ok; this.status = status; this.statusText = statusText; }
    }

    /** The request an HTTP sink sends. */
    public static final class FetchInit {
        public final String method;
        public final Map<String, String> headers;
        public final String body;
        FetchInit(String method, Map<String, String> headers, String body) { this.method = method; this.headers = headers; this.body = body; }
    }

    /** An injectable fetch: {@link #defaultFetch} by default, or a mock in tests. */
    public interface FetchLike { FetchLikeResponse fetch(String url, FetchInit init) throws Exception; }

    public static final class HttpSinkOptions {
        public String format;
        public Map<String, String> headers;
        public FetchLike fetch;
        public String contentType;
        public String name;
        public Double timeoutMs;
        public Map<String, Object> serialize;
        public HttpSinkOptions(String format) { this.format = format; }
    }

    /** A fetch over java.net.http: one POST, the status line mapped to {@link FetchLikeResponse}. */
    public static FetchLike defaultFetch() {
        HttpClient client = HttpClient.newBuilder().build();
        return (url, init) -> {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(30)).method(init.method, HttpRequest.BodyPublishers.ofString(init.body));
            for (Map.Entry<String, String> h : init.headers.entrySet()) b.header(h.getKey(), h.getValue());
            HttpResponse<Void> res = client.send(b.build(), HttpResponse.BodyHandlers.discarding());
            int s = res.statusCode();
            return new FetchLikeResponse(s >= 200 && s < 300, s, null);
        };
    }

    /**
     * An HTTP sink that batches events into one POST: NDJSON for OCSF / ECS, the raw CEF lines for CEF (the body is the lines joined by newlines).
     * Delivery never throws: a network error, a timeout or a non-2xx status is returned as a failure result.
     */
    public static SiemSink httpSink(String url, HttpSinkOptions options) {
        final String format = options.format;
        final String name = options.name != null ? options.name : "http:" + format;
        return new SiemSink() {
            @Override public String name() { return name; }
            @Override public String format() { return format; }
            @Override public SinkResult deliver(List<SiemEvent> events) {
                try {
                    FetchLike doFetch = options.fetch != null ? options.fetch : defaultFetch();
                    List<String> lines = new ArrayList<>();
                    for (SiemEvent e : events) lines.add(e.line);
                    String body = String.join("\n", lines);
                    Map<String, String> headers = new LinkedHashMap<>();
                    String ct = options.contentType != null ? options.contentType : contentType(format);
                    if (ct != null) headers.put("content-type", ct);
                    if (options.headers != null) headers.putAll(options.headers);
                    double t = options.timeoutMs != null ? options.timeoutMs : 10_000.0;
                    long ms = !Double.isNaN(t) && !Double.isInfinite(t) && t > 0 ? (long) t : 10_000L;
                    FetchInit init = new FetchInit("POST", headers, body);
                    CompletableFuture<FetchLikeResponse> f = new CompletableFuture<>();
                    Thread th = new Thread(() -> {
                        try { f.complete(doFetch.fetch(url, init)); } catch (Throwable e) { f.completeExceptionally(e); }
                    });
                    th.setDaemon(true);
                    th.start();
                    FetchLikeResponse res;
                    try {
                        res = f.get(ms, TimeUnit.MILLISECONDS);
                    } catch (TimeoutException te) {
                        th.interrupt();
                        return SinkResult.failure("delivery timed out");
                    } catch (ExecutionException ee) {
                        Throwable c = ee.getCause() != null ? ee.getCause() : ee;
                        return SinkResult.failure(scrubError(messageOf(c)));
                    }
                    if (res.ok) return SinkResult.success();
                    return SinkResult.failure(scrubError("HTTP " + res.status + (res.statusText != null && !res.statusText.isEmpty() ? " " + res.statusText : "")));
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return SinkResult.failure(scrubError(messageOf(ie)));
                } catch (RuntimeException e) {
                    return SinkResult.failure(scrubError(messageOf(e)));
                }
            }
        };
    }

    public static final class ConsoleSinkOptions {
        public String format;
        public Consumer<String> logger;
        public String name;
    }

    /** A sink that writes each event's serialized line to a logger (default standard output). Never throws. */
    public static SiemSink consoleSink(ConsoleSinkOptions options) {
        final String format = options != null && options.format != null ? options.format : "ocsf";
        final Consumer<String> logger = options != null && options.logger != null ? options.logger : System.out::println;
        final String name = options != null && options.name != null ? options.name : "console:" + format;
        return new SiemSink() {
            @Override public String name() { return name; }
            @Override public String format() { return format; }
            @Override public SinkResult deliver(List<SiemEvent> events) {
                try {
                    for (SiemEvent e : events) logger.accept(e.line);
                    return SinkResult.success();
                } catch (RuntimeException e) {
                    return SinkResult.failure(scrubError(messageOf(e)));
                }
            }
        };
    }

    // ---- export orchestration ---------------------------------------------------------------------------------------------------------

    /** Called (log and drop) when delivery fails; wrapped so it can never throw back into the caller. */
    public interface OnError { void accept(Exception error, String sink, int count); }

    public static final class ExportOptions {
        public OnError onError;
        public Map<String, Object> serialize;
    }

    public static final class ExportResult {
        public final boolean ok;
        public final int delivered;
        public final String format;
        public final String error;
        public final int skipped;
        ExportResult(boolean ok, int delivered, String format, String error, int skipped) { this.ok = ok; this.delivered = delivered; this.format = format; this.error = error; this.skipped = skipped; }
        public Map<String, Object> toMap() {
            Map<String, Object> m = map();
            m.put("ok", ok);
            m.put("delivered", intJ(delivered));
            if (format != null) m.put("format", format);
            if (error != null) m.put("error", error);
            if (skipped > 0) m.put("skipped", intJ(skipped));
            return m;
        }
    }

    private static void safeOnError(ExportOptions options, Exception error, String sink, int count) {
        if (options == null || options.onError == null) return;
        try { options.onError.accept(error, sink, count); } catch (RuntimeException e) { /* an onError that throws must not touch the auth path */ }
    }

    /** Export one PCA decision to a sink. Fail-safe: errors are reported via onError and returned, never thrown. */
    public static ExportResult exportDecision(Object record, SiemSink sink, ExportOptions options) {
        List<Object> one = new ArrayList<>();
        one.add(record);
        return exportBatch(one, sink, options);
    }

    /** Export a batch of PCA decisions to a sink in one delivery. Fail-safe, exactly like {@link #exportDecision}. */
    public static ExportResult exportBatch(List<?> records, SiemSink sink, ExportOptions options) {
        String format = sink == null ? null : sink.format();
        int count = 0;
        try {
            List<SiemEvent> events = new ArrayList<>();
            int skipped = 0;
            for (Object r : records) {
                try {
                    events.add(formatDecision(r, format, options == null ? null : options.serialize));
                } catch (RuntimeException e) {
                    skipped++;
                    safeOnError(options, new Exception(scrubError("record could not be serialized: " + messageOf(e))), sink.name(), 1);
                }
            }
            count = events.size();
            if (events.isEmpty() && skipped > 0) return new ExportResult(false, 0, format, "no record could be serialized", skipped);
            SinkResult res = sink.deliver(events);
            if (res.ok) return new ExportResult(true, events.size(), format, null, skipped);
            Exception err = new Exception(scrubError(res.error != null ? res.error : "sink reported a delivery failure"));
            safeOnError(options, err, sink.name(), events.size());
            return new ExportResult(false, 0, format, err.getMessage(), skipped);
        } catch (Exception e) {
            Exception err = new Exception(scrubError(messageOf(e)));
            safeOnError(options, err, sink == null ? "(unknown sink)" : sink.name(), count);
            return new ExportResult(false, 0, format, err.getMessage(), 0);
        }
    }
}
