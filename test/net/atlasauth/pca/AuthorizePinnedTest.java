package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

/**
 * The whole authorize() result, pinned. Every shared fixture, every TypeScript-oracle scenario, a tamper matrix over the
 * PCActn members and a matrix of context / revocation / require / clock variants run through authorize(); the full result
 * (every check in order, every reason, status, decision, assurance, escalation, undo, the bound operation) is hashed per
 * group and compared with test-data/authorize-pinned.tsv. The failing-check sets and reasons of the fixtures and oracle
 * scenarios are independently held to the TypeScript reference by AuthorizeTest and K05AuthorizeDiffTest; this test pins
 * the rest of the result so a change to any branch of the pipeline is seen.
 *
 * A changed or new group fails with lines {@code PINNED <group> <hash>} and the projection, to review and copy into the file.
 */
public class AuthorizePinnedTest {
    static final Path FILE = Path.of("test-data/authorize-pinned.tsv");

    static Object safe(Object v) {
        try { return Json.parse(Json.canonicalize(v)); } catch (RuntimeException e) { return "<" + String.valueOf(v) + ">"; }
    }

    static Map<String, Object> project(Authorize.AuthorizeResult r, Authorize.Operation op) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("allow", r.allow);
        o.put("status", (long) r.status);
        o.put("decision", r.decision);
        List<Object> checks = new ArrayList<>();
        for (Map.Entry<String, String> e : r.checks.entrySet()) checks.add(e.getKey() + "=" + e.getValue());
        o.put("checks", checks);
        o.put("reasons", new ArrayList<Object>(r.reasons));
        o.put("reason", r.reason);
        o.put("missing", r.missing == null ? null : new ArrayList<Object>(r.missing));
        o.put("escalation", r.escalation == null ? null : safe(r.escalation));
        o.put("undo", r.undo == null ? null : safe(r.undo));
        o.put("degraded", r.degraded == null ? null : safe(r.degraded));
        o.put("obligations", r.obligations == null ? null : safe(r.obligations));
        o.put("assurance", safe(r.assurance()));
        o.put("operation", r.operation == null ? null : Arrays.asList(r.operation.verb, r.operation.resource, r.operation.paramsDigest, r.operation.id));
        o.put("bound", Authorize.isAuthorizedFor(r, op));
        o.put("bound_other", op == null ? null : Authorize.isAuthorizedFor(r, Authorize.Operation.of(op.verb, op.resource + "x", op.params)));
        return o;
    }

    final Map<String, List<Object>> groups = new TreeMap<>();

    void add(String group, Authorize.AuthorizeResult r, Authorize.Operation op) {
        groups.computeIfAbsent(group, k -> new ArrayList<>()).add(project(r, op));
    }

    static String sha(String s) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
    }

    // ---- the inputs -----------------------------------------------------------------------------------------------------

    void fixtures() {
        for (Map<String, Object> c : AuthorizeFixtures.cases()) {
            StateStore store = new MemoryStateStore();
            int n = ((List<?>) c.get("steps")).size();
            for (int i = 0; i < n; i++) {
                boolean revoked = Boolean.TRUE.equals(AuthorizeFixtures.step(c, i).get("revoked"));
                Authorize.Input in = AuthorizeFixtures.input(c, i).stateStore(store).isRevoked((p, g) -> revoked);
                add("fixture:" + c.get("name"), Authorize.authorize(AuthorizeFixtures.pcactn(c, i), in), AuthorizeFixtures.operation(c, i));
            }
        }
    }

    void oracle() throws Exception {
        for (Map<String, Object> c : K05AuthorizeDiffTest.of("authorize")) {
            List<Authorize.AuthorizeResult> raw = new ArrayList<>();
            try { K05AuthorizeDiffTest.scenario(K05AuthorizeDiffTest.m(K05AuthorizeDiffTest.args(c).get(0)), raw); } catch (RuntimeException e) { /* a throwing scenario keeps what ran */ }
            for (Authorize.AuthorizeResult r : raw) add("oracle:" + c.get("name"), r, null);
        }
    }

    static final Map<String, Object> BASE_CASE = AuthorizeFixtures.cases().get(0);

    Authorize.AuthorizeResult base(Object pcactn, Function<Authorize.Input, Authorize.Input> edit) {
        Authorize.Input in = AuthorizeFixtures.input(BASE_CASE, 0).stateStore(new MemoryStateStore()).isRevoked((p, g) -> false);
        return Authorize.authorize(pcactn, edit.apply(in));
    }

    static final Object[][] VARIANTS = {{"absent", null}, {"null", null}, {"num", 5L}, {"neg", -1L}, {"str", "x"}, {"empty", ""},
        {"true", true}, {"list", List.of()}, {"list1", List.of("x")}, {"map", Map.of()}};

    static Map<String, Object> edit(Map<String, Object> m, String key, String variant, Object value) {
        Map<String, Object> out = new LinkedHashMap<>(m);
        if (variant.equals("absent")) out.remove(key);
        else out.put(key, value);
        return out;
    }

    @SuppressWarnings("unchecked")
    void tamper() {
        Map<String, Object> pc = AuthorizeFixtures.pcactn(BASE_CASE, 0);
        Authorize.Operation op = AuthorizeFixtures.operation(BASE_CASE, 0);
        add("base", base(pc, in -> in), op);
        for (String k : new TreeMap<>(pc).keySet()) {
            for (Object[] v : VARIANTS) add("tamper:" + k + ":" + v[0], base(edit(pc, k, (String) v[0], v[1]), in -> in), op);
            if (pc.get(k) instanceof Map) {
                Map<String, Object> inner = (Map<String, Object>) pc.get(k);
                for (String j : new TreeMap<>(inner).keySet())
                    for (Object[] v : VARIANTS)
                        add("tamper:" + k + "." + j + ":" + v[0], base(edit(pc, k, "set", edit(inner, j, (String) v[0], v[1])), in -> in), op);
            }
            if (pc.get(k) instanceof List && !((List<?>) pc.get(k)).isEmpty() && ((List<?>) pc.get(k)).get(0) instanceof Map) {
                List<Object> list = new ArrayList<>((List<Object>) pc.get(k));
                Map<String, Object> first = (Map<String, Object>) list.get(0);
                for (String j : new TreeMap<>(first).keySet())
                    for (Object[] v : VARIANTS) {
                        List<Object> l2 = new ArrayList<>(list);
                        l2.set(0, edit(first, j, (String) v[0], v[1]));
                        add("tamper:" + k + "[0]." + j + ":" + v[0], base(edit(pc, k, "set", l2), in -> in), op);
                    }
            }
        }
    }

    void variants() {
        Map<String, Object> pc = AuthorizeFixtures.pcactn(BASE_CASE, 0);
        Authorize.Operation op = AuthorizeFixtures.operation(BASE_CASE, 0);
        Map<String, Object> ctxValues = new LinkedHashMap<>();
        ctxValues.put("reversibility_class", List.of("reversible", "rate_limited", "costly", "irreversible", "other", 5L));
        ctxValues.put("subject", List.of(Map.of("id", "u", "groups", List.of("g")), "s", 5L));
        ctxValues.put("blast_radius", List.of(1L, 1000000L, "x"));
        ctxValues.put("recent_action_times", List.of(List.of(), List.of(AuthorizeFixtures.now() - 1, AuthorizeFixtures.now()), "x"));
        ctxValues.put("env", List.of(Map.of(), Map.of("region", "eu"), 5L));
        ctxValues.put("revocation_state", List.of(Map.of(), "x"));
        ctxValues.put("plan", List.of(Map.of(), "x"));
        for (Map.Entry<String, Object> e : ctxValues.entrySet()) {
            List<?> vs = (List<?>) e.getValue();
            for (int i = 0; i < vs.size(); i++) {
                Map<String, Object> ctx = new LinkedHashMap<>();
                ctx.put(e.getKey(), vs.get(i));
                add("ctx:" + e.getKey() + ":" + i, base(pc, in -> in.context(p -> ctx)), op);
            }
        }
        add("ctx:null", base(pc, in -> in.context(p -> null)), op);
        add("ctx:throws", base(pc, in -> in.context(p -> { throw new IllegalStateException("x"); })), op);
        add("revoked:true", base(pc, in -> in.isRevoked((p, g) -> true)), op);
        add("revoked:null", base(pc, in -> in.isRevoked((p, g) -> null)), op);
        add("revoked:throws", base(pc, in -> in.isRevoked((p, g) -> { throw new IllegalStateException("x"); })), op);
        for (List<String> req : List.of(List.<String>of(), List.of("replay"), List.of("counter"), List.of("policy"), List.of("unknown_check"),
                Arrays.asList("replay", null), List.of("escalation"), List.of("fresh_at"), List.of("provenance_flow"), List.of("undo_window")))
            add("require:" + req, base(pc, in -> in.require(req)), op);
        long now = AuthorizeFixtures.now();
        for (long d : new long[] {-86_400_000L * 365, -60_000L, 60_000L, 86_400_000L * 365})
            add("now:" + d, base(pc, in -> in.now(now + d)), op);
        add("audience:other", base(pc, in -> in.audience("https://other.example")), op);
        add("grant:other", base(pc, in -> in.resolveGrant(ref -> AuthorizeFixtures.grant(AuthorizeFixtures.cases().get(1)))), op);
        add("plan:null", base(pc, in -> in.plan(null)), op);
        Map<String, Object> params2 = new LinkedHashMap<>(op.params == null ? Map.of() : op.params);
        params2.put("extra", 1L);
        add("op:params", base(pc, in -> in.operation(Authorize.Operation.of(op.verb, op.resource, params2))), op);
        add("op:verb", base(pc, in -> in.operation(Authorize.Operation.of(op.verb + "x", op.resource, op.params))), op);
        add("op:resource", base(pc, in -> in.operation(Authorize.Operation.of(op.verb, op.resource + "x", op.params))), op);
        add("op:null", base(pc, in -> in.operation(null)), op);
        add("pcactn:text", base(Json.canonicalize(pc), in -> in), op);
        add("pcactn:bytes", base(Json.canonicalize(pc).getBytes(StandardCharsets.UTF_8), in -> in), op);
        add("pcactn:null", base(null, in -> in), op);
        add("input:null", Authorize.authorize(pc, null), op);
        // replay: the same PCActn twice against one store
        StateStore one = new MemoryStateStore();
        for (int i = 0; i < 2; i++)
            add("replay", Authorize.authorize(pc, AuthorizeFixtures.input(BASE_CASE, 0).stateStore(one).isRevoked((p, g) -> false)), op);
    }

    static Map<String, String> pinned() throws Exception {
        Map<String, String> want = new TreeMap<>();
        if (Files.exists(FILE))
            for (String line : Files.readAllLines(FILE, StandardCharsets.UTF_8)) {
                String[] f = line.strip().split("\t");
                if (f.length == 2) want.put(f[0], f[1]);
            }
        return want;
    }

    /** This test's groups against the file (only the groups whose prefix this test owns). */
    void check(String prefix) throws Exception {
        Map<String, String> want = pinned();
        List<String> bad = new ArrayList<>();
        for (Map.Entry<String, List<Object>> g : groups.entrySet()) {
            String text = Json.canonicalize(g.getValue());
            String h = sha(text);
            if (!h.equals(want.get(g.getKey()))) {
                System.out.println("PINNED\t" + g.getKey() + "\t" + h);
                bad.add(g.getKey() + (want.containsKey(g.getKey()) ? " changed: " : " new: ") + (text.length() > 1500 ? text.substring(0, 1500) + "..." : text));
            }
        }
        for (String k : want.keySet()) if (owns(prefix, k) && !groups.containsKey(k)) bad.add(k + " no longer produced");
        assertTrue(bad.isEmpty(), bad.size() + "/" + groups.size() + " pinned group(s) differ:\n" + String.join("\n", bad));
    }

    static boolean owns(String prefixes, String key) {
        for (String p : prefixes.split(",")) if (key.startsWith(p)) return true;
        return false;
    }

    @Test void fixturesArePinned() throws Exception { fixtures(); check("fixture:"); }
    @Test void oracleScenariosArePinned() throws Exception { oracle(); check("oracle:"); }
    @Test void tamperedMembersArePinned() throws Exception { tamper(); check("base,tamper:"); }
    @Test void inputVariantsArePinned() throws Exception { variants(); check("ctx:,revoked:,require:,now:,audience:,grant:,plan:,op:,pcactn:,input:,replay"); }
}
