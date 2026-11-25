package net.atlasauth.pca.testing;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import net.atlasauth.pca.Facade;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;

/**
 * Testing kit for Proof-Carrying Authority: factories, fakes and assertion helpers so an integrator can test their PCA wiring
 * in process, with no backend and no network. {@link #testAgent} mints a real agent with test defaults, {@link #makePCActn} builds
 * real PCActns from it, and {@link #fakeVerify} runs the real core verifier against them.
 *
 * <p>Nothing here authorizes anything: {@code fakeVerify} stands in for the resource server by rooting the check at the PCActn's
 * own grant and accepting the PCActn's own audience by default, so a clean round trip verifies. It is the real verifier, not a
 * weakened one: tampering is caught exactly as in production. A grant lifted from the artifact is never trusted for a
 * post-quantum root (no pin exists), exactly as the reference refuses it.
 */
public final class TestingKit {
    private TestingKit() {}

    // ---- factories ----

    /** Overrides for {@link #testAgent}; anything left null falls back to a test default. */
    public static final class TestAgentOverrides {
        /** Connector to allowed actions. Default {@code {stripe: [refund]}}. */
        public Map<String, Object> permissions;
        /** Per-action limits. Default {@code {refund: "$500/day"}}; pass an empty map for none. */
        public Map<String, Object> limits;
        /** Plaintext goal (only its salted commitment goes in the grant). Default {@code test}. */
        public String goal;
        /** Default audience of every act. Default {@code ins_test}. */
        public String aud;
        /** The principal (human) key that roots and signs the grant; generated when null. */
        public Keys.SuiteKey principal;
        /** The agent (holder) key that signs PCActns; generated when null. */
        public Keys.SuiteKey holder;
    }

    /** A real agent handle with test defaults. */
    public static Facade.Handle testAgent(TestAgentOverrides ov) {
        TestAgentOverrides o = ov != null ? ov : new TestAgentOverrides();
        Map<String, Object> perms = o.permissions;
        if (perms == null) {
            perms = new LinkedHashMap<>();
            perms.put("stripe", new ArrayList<Object>(List.of("refund")));
        }
        Map<String, Object> limits = o.limits;
        if (limits == null) {
            limits = new LinkedHashMap<>();
            limits.put("refund", "$500/day");
        }
        Keys.SuiteKey principal = o.principal != null ? o.principal : Keys.ed25519(Keys.edGenerate());
        Facade.AgentOptions opts = new Facade.AgentOptions(principal, o.goal != null ? o.goal : "test", perms)
            .limits(limits).aud(o.aud != null ? o.aud : "ins_test");
        if (o.holder != null) opts.holder(o.holder);
        return Facade.agent(opts);
    }

    /** The PCActn and its wire encoding. */
    public record Made(Map<String, Object> pcactn, String encoded) {}

    /** Build a PCActn for one action ({@code counter} auto-increments per holder when null; {@code now} is the clock in ms). */
    public static Made makePCActn(Facade.Handle a, String verb, String resource, Map<String, Object> params, Long counter, Long now) {
        Facade.ActOptions o = new Facade.ActOptions();
        o.counter = counter;
        o.now = now;
        Facade.ActResult r = a.act(verb, resource, params, o);
        return new Made(r.pcactn, r.encoded);
    }

    // ---- fake verifier ----

    /** Options for {@link #fakeVerify} / {@link #expectVerifies} / {@link #expectDenied}. */
    public static final class FakeVerifyOptions {
        /** The verifier's own audience, honoured only when {@link #audienceGiven}: null then opts out entirely. Unset: the PCActn's own aud. */
        public String audience;
        public boolean audienceGiven;
        /** Clock (epoch ms); the wall clock when null. */
        public Long now;
        /** Root grant to verify against; the PCActn's own chain root when null. */
        public Map<String, Object> grant;

        public FakeVerifyOptions audience(String a) { audience = a; audienceGiven = true; return this; }
        public FakeVerifyOptions now(long n) { now = n; return this; }
        public FakeVerifyOptions grant(Map<String, Object> g) { grant = g; return this; }
    }

    /** The verdict: {@code allow}, each check's pass/fail in the verifier's order, and the first failure's reason. */
    public record FakeVerifyResult(boolean allow, Map<String, Boolean> checks, String reason) {}

    private static boolean truthy(Object v) {
        if (v == null || Boolean.FALSE.equals(v)) return false;
        if (v instanceof String) return !((String) v).isEmpty();
        Double d = v instanceof Json.Num || v instanceof Number ? num(v) : null;
        return d == null || !(d == 0.0 || Double.isNaN(d));
    }

    private static Double num(Object v) {
        if (v instanceof Json.Num) {
            try { return Double.parseDouble(((Json.Num) v).raw); } catch (NumberFormatException e) { return null; }
        }
        return v instanceof Number ? ((Number) v).doubleValue() : null;
    }

    /** {@code pcactn.cap_chain[0]} as JavaScript reads it; throws where JavaScript would throw or find nothing. */
    private static Object liftGrant(Object pcactn) {
        if (!(pcactn instanceof Map)) throw new IllegalArgumentException("fakeVerify: PCActn has an empty cap_chain and no grant was supplied via opts.grant");
        Object chain = ((Map<?, ?>) pcactn).get("cap_chain");
        Object first = null;
        if (chain instanceof List && !((List<?>) chain).isEmpty()) first = ((List<?>) chain).get(0);
        else if (chain instanceof String && !((String) chain).isEmpty()) first = ((String) chain).substring(0, 1);
        if (!truthy(first)) throw new IllegalArgumentException("fakeVerify: PCActn has an empty cap_chain and no grant was supplied via opts.grant");
        return first;
    }

    private static FakeVerifyResult denied(String check, String why) {
        Map<String, Boolean> c = new LinkedHashMap<>();
        c.put(check, false);
        return new FakeVerifyResult(false, c, check + ": " + why);
    }

    /**
     * Run the real core verifier against {@code pcactn}, rooting the check at {@code opts.grant} or the PCActn's own chain root and
     * defaulting the audience to the PCActn's own. A lifted grant whose suite is not plain ed25519 is refused (the root key proves
     * nothing about who issued it without a verifier-side pin). Throws when there is no grant to root at.
     */
    @SuppressWarnings("unchecked")
    public static FakeVerifyResult fakeVerify(Object pcactn, FakeVerifyOptions opts) {
        FakeVerifyOptions o = opts != null ? opts : new FakeVerifyOptions();
        Object grant = o.grant != null ? o.grant : liftGrant(pcactn);
        boolean lifted = o.grant == null;
        String audience;
        if (o.audienceGiven && o.audience != null) audience = o.audience;
        else {
            if (!o.audienceGiven && pcactn == null) throw new IllegalArgumentException("fakeVerify: no PCActn");
            Object aud = pcactn instanceof Map ? ((Map<?, ?>) pcactn).get("aud") : null;
            audience = aud instanceof String ? (String) aud : null; // opt-out: the PCActn's own audience (a non-string one fails the wire check)
        }
        if (!(grant instanceof Map)) return denied("wire", "the grant is not an object");
        Map<String, Object> g = (Map<String, Object>) grant;
        if (lifted && g.containsKey("alg") && !"ed25519".equals(g.get("alg"))) {
            return denied("chain", "root suite needs a verifier-side PQ pin; a grant lifted from the artifact is never trusted for it");
        }
        long now = o.now != null ? o.now : System.currentTimeMillis();
        Pca.Verdict v = Pca.verifyPcactn(pcactn, g, now, audience, null, null, null, null, Pca.PlanRoots.SKIP);
        return new FakeVerifyResult(v.allow, new LinkedHashMap<>(v.checks), v.reason);
    }

    private static String failing(FakeVerifyResult r) {
        List<String> names = new ArrayList<>();
        for (Map.Entry<String, Boolean> e : r.checks().entrySet()) if (!e.getValue()) names.add(e.getKey());
        return String.join(", ", names);
    }

    /** Assert that {@code pcactn} verifies; throws an {@link IllegalStateException} naming the failing checks when it does not. */
    public static FakeVerifyResult expectVerifies(Object pcactn, FakeVerifyOptions opts) {
        FakeVerifyResult r = fakeVerify(pcactn, opts);
        if (!r.allow()) {
            throw new IllegalStateException("expectVerifies: PCActn was denied. failing checks: [" + failing(r) + "]"
                + (r.reason() != null && !r.reason().isEmpty() ? " — " + r.reason() : ""));
        }
        return r;
    }

    /** The inverse of {@link #expectVerifies}: throws when {@code pcactn} unexpectedly verifies. */
    public static FakeVerifyResult expectDenied(Object pcactn, FakeVerifyOptions opts) {
        FakeVerifyResult r = fakeVerify(pcactn, opts);
        if (r.allow()) throw new IllegalStateException("expectDenied: PCActn verified but was expected to be denied. checks: " + r.checks());
        return r;
    }

    // ---- in-memory state store ----

    /** Per-holder replay/budget state; a structural stand-in for the state a resource server threads across actions. */
    public static final class MemoryStateStore {
        private final Map<String, Map<String, Object>> m = new ConcurrentHashMap<>();
        /** The state stored under {@code key}, or null. */
        public Map<String, Object> get(String key) { return m.get(key); }
        public void put(String key, Map<String, Object> state) { m.put(key, state); }
    }

    /** An in-memory store; nothing persists beyond the process. */
    public static MemoryStateStore memoryStateStore() { return new MemoryStateStore(); }

    // ---- tampering ----

    @SuppressWarnings("unchecked")
    private static Object stringifyForm(Object v) {
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) out.put(e.getKey(), stringifyForm(e.getValue()));
            return out;
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(stringifyForm(x));
            return out;
        }
        Double d = num(v);
        if (d != null) { // JSON.stringify prints -0 as 0
            Object n = IntentJs.normalize(v instanceof Json.Num ? v : new Json.Num(v.toString()));
            return n.toString().equals("-0") ? new Json.Num("0") : n;
        }
        return v;
    }

    /**
     * Decode an encoded PCActn (strict JSON profile, size-capped), let {@code mutate} corrupt it in place, then re-decode and
     * re-encode it so a test can assert the corruption is caught. A change touching the signed body breaks the leaf signature.
     */
    @SuppressWarnings("unchecked")
    public static String tamper(String encoded, Consumer<Map<String, Object>> mutate) {
        if (Pca.artifactTooLarge(encoded)) throw new IllegalArgumentException(Pca.ARTIFACT_SIZE_REASON);
        Object v = Json.parse(encoded);
        if (!(v instanceof Map)) throw new IllegalArgumentException("decodePCActn: not an object");
        Map<String, Object> rec = new LinkedHashMap<>((Map<String, Object>) v);
        mutate.accept(rec);
        String text = Json.canonicalize(stringifyForm(rec));
        if (Pca.artifactTooLarge(text)) throw new IllegalArgumentException(Pca.ARTIFACT_SIZE_REASON);
        Object back = Json.parse(text);
        if (!(back instanceof Map)) throw new IllegalArgumentException("decodePCActn: not an object");
        return Json.canonicalize(back);
    }

    // ---- adapter acceptance matrix (constants and the route mapping) ----

    public static final String ADAPTER_ACCEPTANCE_AUDIENCE = "payments-rs";

    private static Map<String, Object> outcome(int status, boolean ran, boolean bound) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", status);
        m.put("handlerRan", ran);
        m.put("bound", bound);
        return m;
    }

    /** The outcome every adapter must produce per scenario: status, whether the handler ran, whether the attached operation matches. */
    public static Map<String, Object> adapterAcceptanceExpected() {
        Map<String, Object> m = new LinkedHashMap<>();
        for (String k : new String[] {"over_limit_predicate", "over_limit_max_spend", "body_differs", "other_operation", "escalate_unanswered", "missing_revocation", "missing_store"}) {
            m.put(k, outcome(403, false, false));
        }
        m.put("valid_first", outcome(200, true, true));
        m.put("replay_second", outcome(403, false, false));
        return m;
    }

    /** {@code String(v)} for a JSON value. */
    private static String jsString(Object v) {
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        if (num(v) != null) return IntentJs.normalize(v instanceof Json.Num ? v : new Json.Num(v.toString())).toString();
        return v.toString();
    }

    private static boolean isSpecial(String scheme) {
        switch (scheme) { case "http": case "https": case "ftp": case "ws": case "wss": case "file": return true; default: return false; }
    }

    /**
     * The pathname of {@code url} resolved against a base origin, as a WHATWG URL parser yields it, for the shapes a request carries:
     * absolute and scheme-relative URLs with an authority, rooted and relative paths, dot segments, query and fragment. Only
     * a pathname equal to a route can match, so any other spelling needs no further normalisation. shortcut: percent-encoding of
     * the path is not reproduced (an encoded spelling never equals a route), upgrade if routes ever contain non-ASCII.
     */
    static String pathnameOf(String url) {
        String s = url.replaceAll("^[\\u0000-\\u0020]+|[\\u0000-\\u0020]+$", "").replaceAll("[\\t\\n\\r]", "");
        int cut = s.length();
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) == '?' || s.charAt(i) == '#') { cut = i; break; }
        String rest = s.substring(0, cut);
        java.util.regex.Matcher sm = java.util.regex.Pattern.compile("^([A-Za-z][A-Za-z0-9+.\\-]*):").matcher(rest);
        String path;
        if (sm.find()) {
            String scheme = sm.group(1).toLowerCase(Locale.ROOT);
            rest = rest.substring(sm.end());
            if (!isSpecial(scheme)) {
                if (rest.startsWith("//")) {
                    int end = rest.indexOf('/', 2);
                    path = end < 0 ? "" : rest.substring(end);
                } else if (rest.startsWith("/")) path = rest;
                else return rest; // opaque path: never a route
            } else if (scheme.equals("file")) {
                rest = rest.replace('\\', '/');
                if (rest.startsWith("//")) {
                    int end = rest.indexOf('/', 2);
                    path = end < 0 ? "/" : rest.substring(end);
                } else path = rest.startsWith("/") ? rest : "/" + rest;
            } else {
                rest = rest.replace('\\', '/');
                if (scheme.equals("http") && !rest.startsWith("//")) path = rest.startsWith("/") ? rest : "/" + rest; // same scheme as the base: relative
                else {
                    int slashes = 0;
                    while (slashes < rest.length() && rest.charAt(slashes) == '/') slashes++;
                    rest = rest.substring(slashes);
                    int end = rest.indexOf('/');
                    if ((end < 0 ? rest : rest.substring(0, end)).isEmpty()) throw new IllegalArgumentException("Invalid URL");
                    path = end < 0 ? "/" : rest.substring(end);
                }
            }
        } else {
            rest = rest.replace('\\', '/');
            if (rest.startsWith("//")) {
                String t = rest.substring(2);
                while (t.startsWith("/")) t = t.substring(1);
                int end = t.indexOf('/');
                if ((end < 0 ? t : t.substring(0, end)).isEmpty()) throw new IllegalArgumentException("Invalid URL");
                path = end < 0 ? "/" : t.substring(end);
            } else path = rest.startsWith("/") ? rest : "/" + rest;
        }
        if (path.isEmpty()) return "";
        List<String> out = new ArrayList<>();
        String[] segs = path.substring(1).split("/", -1);
        for (int i = 0; i < segs.length; i++) {
            String seg = segs[i];
            String low = seg.toLowerCase(Locale.ROOT);
            boolean last = i == segs.length - 1;
            if (low.equals("..") || low.equals(".%2e") || low.equals("%2e.") || low.equals("%2e%2e")) {
                if (!out.isEmpty()) out.remove(out.size() - 1);
                if (last) out.add("");
            } else if (low.equals(".") || low.equals("%2e")) {
                if (last) out.add("");
            } else out.add(seg);
        }
        return "/" + String.join("/", out);
    }

    /**
     * The server's mapping from request to operation: a route table on method and path with the JSON body as params. Returns null for
     * an unknown route or a body that is not an object; otherwise {@code {verb, resource, params}}.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> acceptanceOperation(Map<String, Object> req) {
        Object url = req.get("url");
        String path = url instanceof String ? pathnameOf((String) url) : "";
        String key = jsString(req.get("method")).toUpperCase(Locale.ROOT) + " " + path;
        String verb, resource = "payments";
        if (key.equals("POST /payments")) verb = "payments.send";
        else if (key.equals("POST /refunds")) verb = "payments.refund";
        else return null;
        Object body = req.get("body");
        if (!(body instanceof Map)) return null;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("verb", verb);
        m.put("resource", resource);
        m.put("params", body);
        return m;
    }
}
